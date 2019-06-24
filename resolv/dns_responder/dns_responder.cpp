/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dns_responder.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <set>

#include <iostream>
#include <vector>

#define LOG_TAG "DNSResponder"
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <netdutils/InternetAddresses.h>
#include <netdutils/SocketOption.h>

using android::netdutils::enableSockopt;
using android::netdutils::ScopedAddrinfo;

namespace test {

std::string errno2str() {
    char error_msg[512] = { 0 };
    // It actually calls __gnu_strerror_r() which returns the type |char*| rather than |int|.
    // PLOG is an option though it requires lots of changes from ALOGx() to LOG(x).
    return strerror_r(errno, error_msg, sizeof(error_msg));
}

std::string str2hex(const char* buffer, size_t len) {
    std::string str(len*2, '\0');
    for (size_t i = 0 ; i < len ; ++i) {
        static const char* hex = "0123456789ABCDEF";
        uint8_t c = buffer[i];
        str[i*2] = hex[c >> 4];
        str[i*2 + 1] = hex[c & 0x0F];
    }
    return str;
}

std::string addr2str(const sockaddr* sa, socklen_t sa_len) {
    char host_str[NI_MAXHOST] = { 0 };
    int rv = getnameinfo(sa, sa_len, host_str, sizeof(host_str), nullptr, 0,
                         NI_NUMERICHOST);
    if (rv == 0) return std::string(host_str);
    return std::string();
}

/* DNS struct helpers */

const char* dnstype2str(unsigned dnstype) {
    static std::unordered_map<unsigned, const char*> kTypeStrs = {
        { ns_type::ns_t_a, "A" },
        { ns_type::ns_t_ns, "NS" },
        { ns_type::ns_t_md, "MD" },
        { ns_type::ns_t_mf, "MF" },
        { ns_type::ns_t_cname, "CNAME" },
        { ns_type::ns_t_soa, "SOA" },
        { ns_type::ns_t_mb, "MB" },
        { ns_type::ns_t_mb, "MG" },
        { ns_type::ns_t_mr, "MR" },
        { ns_type::ns_t_null, "NULL" },
        { ns_type::ns_t_wks, "WKS" },
        { ns_type::ns_t_ptr, "PTR" },
        { ns_type::ns_t_hinfo, "HINFO" },
        { ns_type::ns_t_minfo, "MINFO" },
        { ns_type::ns_t_mx, "MX" },
        { ns_type::ns_t_txt, "TXT" },
        { ns_type::ns_t_rp, "RP" },
        { ns_type::ns_t_afsdb, "AFSDB" },
        { ns_type::ns_t_x25, "X25" },
        { ns_type::ns_t_isdn, "ISDN" },
        { ns_type::ns_t_rt, "RT" },
        { ns_type::ns_t_nsap, "NSAP" },
        { ns_type::ns_t_nsap_ptr, "NSAP-PTR" },
        { ns_type::ns_t_sig, "SIG" },
        { ns_type::ns_t_key, "KEY" },
        { ns_type::ns_t_px, "PX" },
        { ns_type::ns_t_gpos, "GPOS" },
        { ns_type::ns_t_aaaa, "AAAA" },
        { ns_type::ns_t_loc, "LOC" },
        { ns_type::ns_t_nxt, "NXT" },
        { ns_type::ns_t_eid, "EID" },
        { ns_type::ns_t_nimloc, "NIMLOC" },
        { ns_type::ns_t_srv, "SRV" },
        { ns_type::ns_t_naptr, "NAPTR" },
        { ns_type::ns_t_kx, "KX" },
        { ns_type::ns_t_cert, "CERT" },
        { ns_type::ns_t_a6, "A6" },
        { ns_type::ns_t_dname, "DNAME" },
        { ns_type::ns_t_sink, "SINK" },
        { ns_type::ns_t_opt, "OPT" },
        { ns_type::ns_t_apl, "APL" },
        { ns_type::ns_t_tkey, "TKEY" },
        { ns_type::ns_t_tsig, "TSIG" },
        { ns_type::ns_t_ixfr, "IXFR" },
        { ns_type::ns_t_axfr, "AXFR" },
        { ns_type::ns_t_mailb, "MAILB" },
        { ns_type::ns_t_maila, "MAILA" },
        { ns_type::ns_t_any, "ANY" },
        { ns_type::ns_t_zxfr, "ZXFR" },
    };
    auto it = kTypeStrs.find(dnstype);
    static const char* kUnknownStr{ "UNKNOWN" };
    if (it == kTypeStrs.end()) return kUnknownStr;
    return it->second;
}

const char* dnsclass2str(unsigned dnsclass) {
    static std::unordered_map<unsigned, const char*> kClassStrs = {
        { ns_class::ns_c_in , "Internet" },
        { 2, "CSNet" },
        { ns_class::ns_c_chaos, "ChaosNet" },
        { ns_class::ns_c_hs, "Hesiod" },
        { ns_class::ns_c_none, "none" },
        { ns_class::ns_c_any, "any" }
    };
    auto it = kClassStrs.find(dnsclass);
    static const char* kUnknownStr{ "UNKNOWN" };
    if (it == kClassStrs.end()) return kUnknownStr;
    return it->second;
}

const char* DNSName::read(const char* buffer, const char* buffer_end) {
    const char* cur = buffer;
    bool last = false;
    do {
        cur = parseField(cur, buffer_end, &last);
        if (cur == nullptr) {
            LOG(ERROR) << "parsing failed at line " << __LINE__;
            return nullptr;
        }
    } while (!last);
    return cur;
}

char* DNSName::write(char* buffer, const char* buffer_end) const {
    char* buffer_cur = buffer;
    for (size_t pos = 0 ; pos < name.size() ; ) {
        size_t dot_pos = name.find('.', pos);
        if (dot_pos == std::string::npos) {
            // Sanity check, should never happen unless parseField is broken.
            LOG(ERROR) << "logic error: all names are expected to end with a '.'";
            return nullptr;
        }
        const size_t len = dot_pos - pos;
        if (len >= 256) {
            LOG(ERROR) << "name component '" << name.substr(pos, dot_pos - pos) << "' is " << len
                       << " long, but max is 255";
            return nullptr;
        }
        if (buffer_cur + sizeof(uint8_t) + len > buffer_end) {
            LOG(ERROR) << "buffer overflow at line " << __LINE__;
            return nullptr;
        }
        *buffer_cur++ = len;
        buffer_cur = std::copy(std::next(name.begin(), pos),
                               std::next(name.begin(), dot_pos),
                               buffer_cur);
        pos = dot_pos + 1;
    }
    // Write final zero.
    *buffer_cur++ = 0;
    return buffer_cur;
}

const char* DNSName::parseField(const char* buffer, const char* buffer_end, bool* last) {
    if (buffer + sizeof(uint8_t) > buffer_end) {
        LOG(ERROR) << "parsing failed at line " << __LINE__;
        return nullptr;
    }
    unsigned field_type = *buffer >> 6;
    unsigned ofs = *buffer & 0x3F;
    const char* cur = buffer + sizeof(uint8_t);
    if (field_type == 0) {
        // length + name component
        if (ofs == 0) {
            *last = true;
            return cur;
        }
        if (cur + ofs > buffer_end) {
            LOG(ERROR) << "parsing failed at line " << __LINE__;
            return nullptr;
        }
        name.append(cur, ofs);
        name.push_back('.');
        return cur + ofs;
    } else if (field_type == 3) {
        LOG(ERROR) << "name compression not implemented";
        return nullptr;
    }
    LOG(ERROR) << "invalid name field type";
    return nullptr;
}

const char* DNSQuestion::read(const char* buffer, const char* buffer_end) {
    const char* cur = qname.read(buffer, buffer_end);
    if (cur == nullptr) {
        LOG(ERROR) << "parsing failed at line " << __LINE__;
        return nullptr;
    }
    if (cur + 2*sizeof(uint16_t) > buffer_end) {
        LOG(ERROR) << "parsing failed at line " << __LINE__;
        return nullptr;
    }
    qtype = ntohs(*reinterpret_cast<const uint16_t*>(cur));
    qclass = ntohs(*reinterpret_cast<const uint16_t*>(cur + sizeof(uint16_t)));
    return cur + 2*sizeof(uint16_t);
}

char* DNSQuestion::write(char* buffer, const char* buffer_end) const {
    char* buffer_cur = qname.write(buffer, buffer_end);
    if (buffer_cur == nullptr) return nullptr;
    if (buffer_cur + 2*sizeof(uint16_t) > buffer_end) {
        LOG(ERROR) << "buffer overflow on line " << __LINE__;
        return nullptr;
    }
    *reinterpret_cast<uint16_t*>(buffer_cur) = htons(qtype);
    *reinterpret_cast<uint16_t*>(buffer_cur + sizeof(uint16_t)) = htons(qclass);
    return buffer_cur + 2 * sizeof(uint16_t);
}

std::string DNSQuestion::toString() const {
    char buffer[4096];
    int len = snprintf(buffer, sizeof(buffer), "Q<%s,%s,%s>", qname.name.c_str(),
                       dnstype2str(qtype), dnsclass2str(qclass));
    return std::string(buffer, len);
}

const char* DNSRecord::read(const char* buffer, const char* buffer_end) {
    const char* cur = name.read(buffer, buffer_end);
    if (cur == nullptr) {
        LOG(ERROR) << "parsing failed at line " << __LINE__;
        return nullptr;
    }
    unsigned rdlen = 0;
    cur = readIntFields(cur, buffer_end, &rdlen);
    if (cur == nullptr) {
        LOG(ERROR) << "parsing failed at line " << __LINE__;
        return nullptr;
    }
    if (cur + rdlen > buffer_end) {
        LOG(ERROR) << "parsing failed at line " << __LINE__;
        return nullptr;
    }
    rdata.assign(cur, cur + rdlen);
    return cur + rdlen;
}

char* DNSRecord::write(char* buffer, const char* buffer_end) const {
    char* buffer_cur = name.write(buffer, buffer_end);
    if (buffer_cur == nullptr) return nullptr;
    buffer_cur = writeIntFields(rdata.size(), buffer_cur, buffer_end);
    if (buffer_cur == nullptr) return nullptr;
    if (buffer_cur + rdata.size() > buffer_end) {
        LOG(ERROR) << "buffer overflow on line " << __LINE__;
        return nullptr;
    }
    return std::copy(rdata.begin(), rdata.end(), buffer_cur);
}

std::string DNSRecord::toString() const {
    char buffer[4096];
    int len = snprintf(buffer, sizeof(buffer), "R<%s,%s,%s>", name.name.c_str(), dnstype2str(rtype),
                       dnsclass2str(rclass));
    return std::string(buffer, len);
}

const char* DNSRecord::readIntFields(const char* buffer, const char* buffer_end,
                                     unsigned* rdlen) {
    if (buffer + sizeof(IntFields) > buffer_end ) {
        LOG(ERROR) << "parsing failed at line " << __LINE__;
        return nullptr;
    }
    const auto& intfields = *reinterpret_cast<const IntFields*>(buffer);
    rtype = ntohs(intfields.rtype);
    rclass = ntohs(intfields.rclass);
    ttl = ntohl(intfields.ttl);
    *rdlen = ntohs(intfields.rdlen);
    return buffer + sizeof(IntFields);
}

char* DNSRecord::writeIntFields(unsigned rdlen, char* buffer,
                                const char* buffer_end) const {
    if (buffer + sizeof(IntFields) > buffer_end ) {
        LOG(ERROR) << "buffer overflow on line " << __LINE__;
        return nullptr;
    }
    auto& intfields = *reinterpret_cast<IntFields*>(buffer);
    intfields.rtype = htons(rtype);
    intfields.rclass = htons(rclass);
    intfields.ttl = htonl(ttl);
    intfields.rdlen = htons(rdlen);
    return buffer + sizeof(IntFields);
}

const char* DNSHeader::read(const char* buffer, const char* buffer_end) {
    unsigned qdcount;
    unsigned ancount;
    unsigned nscount;
    unsigned arcount;
    const char* cur = readHeader(buffer, buffer_end, &qdcount, &ancount, &nscount, &arcount);
    if (cur == nullptr) {
        LOG(ERROR) << "parsing failed at line " << __LINE__;
        return nullptr;
    }
    if (qdcount) {
        questions.resize(qdcount);
        for (unsigned i = 0 ; i < qdcount ; ++i) {
            cur = questions[i].read(cur, buffer_end);
            if (cur == nullptr) {
                LOG(ERROR) << "parsing failed at line " << __LINE__;
                return nullptr;
            }
        }
    }
    if (ancount) {
        answers.resize(ancount);
        for (unsigned i = 0 ; i < ancount ; ++i) {
            cur = answers[i].read(cur, buffer_end);
            if (cur == nullptr) {
                LOG(ERROR) << "parsing failed at line " << __LINE__;
                return nullptr;
            }
        }
    }
    if (nscount) {
        authorities.resize(nscount);
        for (unsigned i = 0 ; i < nscount ; ++i) {
            cur = authorities[i].read(cur, buffer_end);
            if (cur == nullptr) {
                LOG(ERROR) << "parsing failed at line " << __LINE__;
                return nullptr;
            }
        }
    }
    if (arcount) {
        additionals.resize(arcount);
        for (unsigned i = 0 ; i < arcount ; ++i) {
            cur = additionals[i].read(cur, buffer_end);
            if (cur == nullptr) {
                LOG(ERROR) << "parsing failed at line " << __LINE__;
                return nullptr;
            }
        }
    }
    return cur;
}

char* DNSHeader::write(char* buffer, const char* buffer_end) const {
    if (buffer + sizeof(Header) > buffer_end) {
        LOG(ERROR) << "buffer overflow on line " << __LINE__;
        return nullptr;
    }
    Header& header = *reinterpret_cast<Header*>(buffer);
    // bytes 0-1
    header.id = htons(id);
    // byte 2: 7:qr, 3-6:opcode, 2:aa, 1:tr, 0:rd
    header.flags0 = (qr << 7) | (opcode << 3) | (aa << 2) | (tr << 1) | rd;
    // byte 3: 7:ra, 6:zero, 5:ad, 4:cd, 0-3:rcode
    // Fake behavior: if the query set the "ad" bit, set it in the response too.
    // In a real server, this should be set only if the data is authentic and the
    // query contained an "ad" bit or DNSSEC extensions.
    header.flags1 = (ad << 5) | rcode;
    // rest of header
    header.qdcount = htons(questions.size());
    header.ancount = htons(answers.size());
    header.nscount = htons(authorities.size());
    header.arcount = htons(additionals.size());
    char* buffer_cur = buffer + sizeof(Header);
    for (const DNSQuestion& question : questions) {
        buffer_cur = question.write(buffer_cur, buffer_end);
        if (buffer_cur == nullptr) return nullptr;
    }
    for (const DNSRecord& answer : answers) {
        buffer_cur = answer.write(buffer_cur, buffer_end);
        if (buffer_cur == nullptr) return nullptr;
    }
    for (const DNSRecord& authority : authorities) {
        buffer_cur = authority.write(buffer_cur, buffer_end);
        if (buffer_cur == nullptr) return nullptr;
    }
    for (const DNSRecord& additional : additionals) {
        buffer_cur = additional.write(buffer_cur, buffer_end);
        if (buffer_cur == nullptr) return nullptr;
    }
    return buffer_cur;
}

std::string DNSHeader::toString() const {
    // TODO
    return std::string();
}

const char* DNSHeader::readHeader(const char* buffer, const char* buffer_end,
                                  unsigned* qdcount, unsigned* ancount,
                                  unsigned* nscount, unsigned* arcount) {
    if (buffer + sizeof(Header) > buffer_end)
        return nullptr;
    const auto& header = *reinterpret_cast<const Header*>(buffer);
    // bytes 0-1
    id = ntohs(header.id);
    // byte 2: 7:qr, 3-6:opcode, 2:aa, 1:tr, 0:rd
    qr = header.flags0 >> 7;
    opcode = (header.flags0 >> 3) & 0x0F;
    aa = (header.flags0 >> 2) & 1;
    tr = (header.flags0 >> 1) & 1;
    rd = header.flags0 & 1;
    // byte 3: 7:ra, 6:zero, 5:ad, 4:cd, 0-3:rcode
    ra = header.flags1 >> 7;
    ad = (header.flags1 >> 5) & 1;
    rcode = header.flags1 & 0xF;
    // rest of header
    *qdcount = ntohs(header.qdcount);
    *ancount = ntohs(header.ancount);
    *nscount = ntohs(header.nscount);
    *arcount = ntohs(header.arcount);
    return buffer + sizeof(Header);
}

/* DNS responder */

DNSResponder::DNSResponder(std::string listen_address, std::string listen_service,
                           ns_rcode error_rcode)
    : listen_address_(std::move(listen_address)),
      listen_service_(std::move(listen_service)),
      error_rcode_(error_rcode) {}

DNSResponder::~DNSResponder() {
    stopServer();
}

void DNSResponder::addMapping(const std::string& name, ns_type type, const std::string& addr) {
    std::lock_guard lock(mappings_mutex_);
    auto it = mappings_.find(QueryKey(name, type));
    if (it != mappings_.end()) {
        LOG(INFO) << "Overwriting mapping for (" << name << ", " << dnstype2str(type)
                  << "), previous address " << it->second << " new address " << addr;
        it->second = addr;
        return;
    }
    mappings_.try_emplace({name, type}, addr);
}

void DNSResponder::removeMapping(const std::string& name, ns_type type) {
    std::lock_guard lock(mappings_mutex_);
    auto it = mappings_.find(QueryKey(name, type));
    if (it != mappings_.end()) {
        LOG(ERROR) << "Cannot remove mapping mapping from (" << name << ", " << dnstype2str(type)
                   << "), not present";
        return;
    }
    mappings_.erase(it);
}

void DNSResponder::setResponseProbability(double response_probability) {
    response_probability_ = response_probability;
}

void DNSResponder::setEdns(Edns edns) {
    edns_ = edns;
}

bool DNSResponder::running() const {
    return socket_.get() != -1;
}

bool DNSResponder::startServer() {
    if (running()) {
        LOG(ERROR) << "server already running";
        return false;
    }

    // Set up UDP socket.
    addrinfo ai_hints{
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_flags = AI_PASSIVE
    };
    addrinfo* ai_res = nullptr;
    int rv = getaddrinfo(listen_address_.c_str(), listen_service_.c_str(),
                         &ai_hints, &ai_res);
    ScopedAddrinfo ai_res_cleanup(ai_res);
    if (rv) {
        LOG(ERROR) << "getaddrinfo(" << listen_address_ << ", " << listen_service_
                   << ") failed: " << gai_strerror(rv);
        return false;
    }
    for (const addrinfo* ai = ai_res ; ai ; ai = ai->ai_next) {
        socket_.reset(socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK, ai->ai_protocol));
        if (socket_.get() < 0) {
            PLOG(INFO) << "ignore creating socket " << socket_.get() << " failed";
            continue;
        }
        enableSockopt(socket_.get(), SOL_SOCKET, SO_REUSEPORT).ignoreError();
        enableSockopt(socket_.get(), SOL_SOCKET, SO_REUSEADDR).ignoreError();
        std::string host_str = addr2str(ai->ai_addr, ai->ai_addrlen);
        if (bind(socket_.get(), ai->ai_addr, ai->ai_addrlen)) {
            LOG(INFO) << "failed to bind UDP " << host_str << ":" << listen_service_;
            continue;
        }
        LOG(INFO) << "bound to UDP " << host_str << ":" << listen_service_;
        break;
    }

    // Set up eventfd socket.
    event_fd_.reset(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
    if (event_fd_.get() == -1) {
        PLOG(ERROR) << "failed to create eventfd " << event_fd_.get();
        return false;
    }

    // Set up epoll socket.
    epoll_fd_.reset(epoll_create1(EPOLL_CLOEXEC));
    if (epoll_fd_.get() < 0) {
        PLOG(ERROR) << "epoll_create1() failed on fd " << epoll_fd_.get();
        return false;
    }

    LOG(INFO) << "adding socket " << socket_.get() << " to epoll";
    if (!addFd(socket_.get(), EPOLLIN)) {
        LOG(ERROR) << "failed to add the socket " << socket_.get() << " to epoll";
        return false;
    }
    LOG(INFO) << "adding eventfd " << event_fd_.get() << " to epoll";
    if (!addFd(event_fd_.get(), EPOLLIN)) {
        LOG(ERROR) << "failed to add the eventfd " << event_fd_.get() << " to epoll";
        return false;
    }

    {
        std::lock_guard lock(update_mutex_);
        handler_thread_ = std::thread(&DNSResponder::requestHandler, this);
    }
    LOG(INFO) << "server started successfully";
    return true;
}

bool DNSResponder::stopServer() {
    std::lock_guard lock(update_mutex_);
    if (!running()) {
        LOG(ERROR) << "server not running";
        return false;
    }
    LOG(INFO) << "stopping server";
    if (!sendToEventFd()) {
        return false;
    }
    handler_thread_.join();
    epoll_fd_.reset();
    socket_.reset();
    LOG(INFO) << "server stopped successfully";
    return true;
}

std::vector<std::pair<std::string, ns_type >> DNSResponder::queries() const {
    std::lock_guard lock(queries_mutex_);
    return queries_;
}

std::string DNSResponder::dumpQueries() const {
    std::lock_guard lock(queries_mutex_);
    std::string out;
    for (const auto& q : queries_) {
        out += "{\"" + q.first + "\", " + std::to_string(q.second) + "} ";
    }
    return out;
}

void DNSResponder::clearQueries() {
    std::lock_guard lock(queries_mutex_);
    queries_.clear();
}

void DNSResponder::requestHandler() {
    epoll_event evs[EPOLL_MAX_EVENTS];
    while (true) {
        int n = epoll_wait(epoll_fd_.get(), evs, EPOLL_MAX_EVENTS, -1);
        if (n <= 0) {
            PLOG(ERROR) << "epoll_wait() failed, n=" << n;
            return;
        }

        for (int i = 0; i < n; i++) {
            const int fd = evs[i].data.fd;
            const uint32_t events = evs[i].events;
            if (fd == event_fd_.get() && (events & (EPOLLIN | EPOLLERR))) {
                handleEventFd();
                return;
            } else if (fd == socket_.get() && (events & (EPOLLIN | EPOLLERR))) {
                handleQuery();
            } else {
                LOG(WARNING) << "unexpected epoll events " << events << " on fd " << fd;
            }
        }
    }
}

bool DNSResponder::handleDNSRequest(const char* buffer, ssize_t len,
                                    char* response, size_t* response_len)
                                    const {
    LOG(DEBUG) << "request: '" << str2hex(buffer, len) << "'";
    const char* buffer_end = buffer + len;
    DNSHeader header;
    const char* cur = header.read(buffer, buffer_end);
    // TODO(imaipi): for now, unparsable messages are silently dropped, fix.
    if (cur == nullptr) {
        LOG(ERROR) << "failed to parse query";
        return false;
    }
    if (header.qr) {
        LOG(ERROR) << "response received instead of a query";
        return false;
    }
    if (header.opcode != ns_opcode::ns_o_query) {
        LOG(INFO) << "unsupported request opcode received";
        return makeErrorResponse(&header, ns_rcode::ns_r_notimpl, response,
                                 response_len);
    }
    if (header.questions.empty()) {
        LOG(INFO) << "no questions present";
        return makeErrorResponse(&header, ns_rcode::ns_r_formerr, response,
                                 response_len);
    }
    if (!header.answers.empty()) {
        LOG(INFO) << "already " << header.answers.size() << " answers present in query";
        return makeErrorResponse(&header, ns_rcode::ns_r_formerr, response,
                                 response_len);
    }

    if (edns_ == Edns::FORMERR_UNCOND) {
        LOG(INFO) << "force to return RCODE FORMERR";
        return makeErrorResponse(&header, ns_rcode::ns_r_formerr, response, response_len);
    }

    if (!header.additionals.empty() && edns_ != Edns::ON) {
        LOG(INFO) << "DNS request has an additional section (assumed EDNS). Simulating an ancient "
                     "(pre-EDNS) server, and returning "
                  << (edns_ == Edns::FORMERR_ON_EDNS ? "RCODE FORMERR." : "no response.");
        if (edns_ == Edns::FORMERR_ON_EDNS) {
            return makeErrorResponse(&header, ns_rcode::ns_r_formerr, response, response_len);
        }
        // No response.
        return false;
    }
    {
        std::lock_guard lock(queries_mutex_);
        for (const DNSQuestion& question : header.questions) {
            queries_.push_back(make_pair(question.qname.name,
                                         ns_type(question.qtype)));
        }
    }

    // Ignore requests with the preset probability.
    auto constexpr bound = std::numeric_limits<unsigned>::max();
    if (arc4random_uniform(bound) > bound * response_probability_) {
        if (error_rcode_ < 0) {
            LOG(ERROR) << "Returning no response";
            return false;
        } else {
            LOG(INFO) << "returning RCODE " << static_cast<int>(error_rcode_)
                      << " in accordance with probability distribution";
            return makeErrorResponse(&header, error_rcode_, response, response_len);
        }
    }

    for (const DNSQuestion& question : header.questions) {
        if (question.qclass != ns_class::ns_c_in &&
            question.qclass != ns_class::ns_c_any) {
            LOG(INFO) << "unsupported question class " << question.qclass;
            return makeErrorResponse(&header, ns_rcode::ns_r_notimpl, response,
                                     response_len);
        }

        if (!addAnswerRecords(question, &header.answers)) {
            return makeErrorResponse(&header, ns_rcode::ns_r_servfail, response, response_len);
        }
    }

    header.qr = true;
    char* response_cur = header.write(response, response + *response_len);
    if (response_cur == nullptr) {
        return false;
    }
    *response_len = response_cur - response;
    return true;
}

bool DNSResponder::addAnswerRecords(const DNSQuestion& question,
                                    std::vector<DNSRecord>* answers) const {
    std::lock_guard guard(mappings_mutex_);
    std::string rname = question.qname.name;
    std::vector<int> rtypes;

    if (question.qtype == ns_type::ns_t_a || question.qtype == ns_type::ns_t_aaaa ||
        question.qtype == ns_type::ns_t_ptr)
        rtypes.push_back(ns_type::ns_t_cname);
    rtypes.push_back(question.qtype);
    for (int rtype : rtypes) {
        std::set<std::string> cnames_Loop;
        std::unordered_map<QueryKey, std::string, QueryKeyHash>::const_iterator it;
        while ((it = mappings_.find(QueryKey(rname, rtype))) != mappings_.end()) {
            if (rtype == ns_type::ns_t_cname) {
                // When detect CNAME infinite loops by cnames_Loop, it won't save the duplicate one.
                // As following, the query will stop on loop3 by detecting the same cname.
                // loop1.{"a.xxx.com", ns_type::ns_t_cname, "b.xxx.com"}(insert in answer record)
                // loop2.{"b.xxx.com", ns_type::ns_t_cname, "a.xxx.com"}(insert in answer record)
                // loop3.{"a.xxx.com", ns_type::ns_t_cname, "b.xxx.com"}(When the same cname record
                //   is found in cnames_Loop already, break the query loop.)
                if (cnames_Loop.find(it->first.name) != cnames_Loop.end()) break;
                cnames_Loop.insert(it->first.name);
            }
            DNSRecord record{
                    .name = {.name = it->first.name},
                    .rtype = it->first.type,
                    .rclass = ns_class::ns_c_in,
                    .ttl = 5,  // seconds
            };
            if (!fillAnswerRdata(it->second, record)) return false;
            answers->push_back(std::move(record));
            if (rtype != ns_type::ns_t_cname) break;
            rname = it->second;
        }
    }

    if (answers->size() == 0) {
        // TODO(imaipi): handle correctly
        LOG(INFO) << "no mapping found for " << question.qname.name << " "
                  << dnstype2str(question.qtype) << ", lazily refusing to add an answer";
    }

    return true;
}

bool DNSResponder::fillAnswerRdata(const std::string& rdatastr, DNSRecord& record) {
    if (record.rtype == ns_type::ns_t_a) {
        record.rdata.resize(4);
        if (inet_pton(AF_INET, rdatastr.c_str(), record.rdata.data()) != 1) {
            LOG(ERROR) << "inet_pton(AF_INET, " << rdatastr << ") failed";
            return false;
        }
    } else if (record.rtype == ns_type::ns_t_aaaa) {
        record.rdata.resize(16);
        if (inet_pton(AF_INET6, rdatastr.c_str(), record.rdata.data()) != 1) {
            LOG(ERROR) << "inet_pton(AF_INET6, " << rdatastr << ") failed";
            return false;
        }
    } else if ((record.rtype == ns_type::ns_t_ptr) || (record.rtype == ns_type::ns_t_cname)) {
        constexpr char delimiter = '.';
        std::string name = rdatastr;
        std::vector<char> rdata;

        // Generating PTRDNAME field(section 3.3.12) or CNAME field(section 3.3.1) in rfc1035.
        // The "name" should be an absolute domain name which ends in a dot.
        if (name.back() != delimiter) {
            LOG(ERROR) << "invalid absolute domain name";
            return false;
        }
        name.pop_back();  // remove the dot in tail
        for (const std::string& label : android::base::Split(name, {delimiter})) {
            // The length of label is limited to 63 octets or less. See RFC 1035 section 3.1.
            if (label.length() == 0 || label.length() > 63) {
                LOG(ERROR) << "invalid label length";
                return false;
            }

            rdata.push_back(label.length());
            rdata.insert(rdata.end(), label.begin(), label.end());
        }
        rdata.push_back(0);  // Length byte of zero terminates the label list

        // The length of domain name is limited to 255 octets or less. See RFC 1035 section 3.1.
        if (rdata.size() > 255) {
            LOG(ERROR) << "invalid name length";
            return false;
        }
        record.rdata = move(rdata);
    } else {
        LOG(ERROR) << "unhandled qtype " << dnstype2str(record.rtype);
        return false;
    }
    return true;
}

bool DNSResponder::makeErrorResponse(DNSHeader* header, ns_rcode rcode,
                                     char* response, size_t* response_len)
                                     const {
    header->answers.clear();
    header->authorities.clear();
    header->additionals.clear();
    header->rcode = rcode;
    header->qr = true;
    char* response_cur = header->write(response, response + *response_len);
    if (response_cur == nullptr) return false;
    *response_len = response_cur - response;
    return true;
}

void DNSResponder::setDeferredResp(bool deferred_resp) {
    std::lock_guard<std::mutex> guard(cv_mutex_for_deferred_resp_);
    deferred_resp_ = deferred_resp;
    if (!deferred_resp_) {
        cv_for_deferred_resp_.notify_one();
    }
}

bool DNSResponder::addFd(int fd, uint32_t events) {
    epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, fd, &ev) < 0) {
        PLOG(ERROR) << "epoll_ctl() for socket " << fd << " failed";
        return false;
    }
    return true;
}

void DNSResponder::handleQuery() {
    char buffer[4096];
    sockaddr_storage sa;
    socklen_t sa_len = sizeof(sa);
    ssize_t len;
    do {
        len = recvfrom(socket_.get(), buffer, sizeof(buffer), 0, (sockaddr*)&sa, &sa_len);
    } while (len < 0 && (errno == EAGAIN || errno == EINTR));
    if (len <= 0) {
        PLOG(INFO) << "recvfrom() failed, len=" << len;
        return;
    }
    LOG(DEBUG) << "read " << len << " bytes";
    std::lock_guard lock(cv_mutex_);
    char response[4096];
    size_t response_len = sizeof(response);
    if (handleDNSRequest(buffer, len, response, &response_len) && response_len > 0) {
        // place wait_for after handleDNSRequest() so we can check the number of queries in
        // test case before it got responded.
        std::unique_lock guard(cv_mutex_for_deferred_resp_);
        cv_for_deferred_resp_.wait(
                guard, [this]() REQUIRES(cv_mutex_for_deferred_resp_) { return !deferred_resp_; });

        len = sendto(socket_.get(), response, response_len, 0,
                     reinterpret_cast<const sockaddr*>(&sa), sa_len);
        std::string host_str = addr2str(reinterpret_cast<const sockaddr*>(&sa), sa_len);
        if (len > 0) {
            LOG(DEBUG) << "sent " << len << " bytes to " << host_str;
        } else {
            PLOG(INFO) << "sendto() failed for " << host_str;
        }
        // Test that the response is actually a correct DNS message.
        const char* response_end = response + len;
        DNSHeader header;
        const char* cur = header.read(response, response_end);
        if (cur == nullptr) LOG(WARNING) << "response is flawed";
    } else {
        LOG(WARNING) << "not responding";
    }
    cv.notify_one();
    return;
}

bool DNSResponder::sendToEventFd() {
    const uint64_t data = 1;
    if (const ssize_t rt = write(event_fd_.get(), &data, sizeof(data)); rt != sizeof(data)) {
        PLOG(ERROR) << "failed to write eventfd, rt=" << rt;
        return false;
    }
    return true;
}

void DNSResponder::handleEventFd() {
    int64_t data;
    if (const ssize_t rt = read(event_fd_.get(), &data, sizeof(data)); rt != sizeof(data)) {
        PLOG(INFO) << "ignore reading eventfd failed, rt=" << rt;
    }
}

}  // namespace test
