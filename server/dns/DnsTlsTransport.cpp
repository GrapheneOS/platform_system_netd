/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "dns/DnsTlsTransport.h"

#include <algorithm>
#include <iterator>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>

#define LOG_TAG "DnsTlsTransport"
#define DBG 0

#include "log/log.h"
#include "Fwmark.h"
#undef ADD  // already defined in nameser.h
#include "NetdConstants.h"
#include "Permission.h"

namespace {

// Returns a tuple of references to the elements of a.
auto make_tie(const sockaddr_in& a) {
    return std::tie(a.sin_port, a.sin_addr.s_addr);
}

// Returns a tuple of references to the elements of a.
auto make_tie(const sockaddr_in6& a) {
    // Skip flowinfo, which is not relevant.
    return std::tie(
        a.sin6_port,
        a.sin6_addr,
        a.sin6_scope_id
    );
}

} // namespace

// These binary operators make sockaddr_storage comparable.  They need to be
// in the global namespace so that the std::tuple < and == operators can see them.
static bool operator <(const in6_addr& x, const in6_addr& y) {
    return std::lexicographical_compare(
            std::begin(x.s6_addr), std::end(x.s6_addr),
            std::begin(y.s6_addr), std::end(y.s6_addr));
}

static bool operator ==(const in6_addr& x, const in6_addr& y) {
    return std::equal(
            std::begin(x.s6_addr), std::end(x.s6_addr),
            std::begin(y.s6_addr), std::end(y.s6_addr));
}

static bool operator <(const sockaddr_storage& x, const sockaddr_storage& y) {
    if (x.ss_family != y.ss_family) {
        return x.ss_family < y.ss_family;
    }
    // Same address family.
    if (x.ss_family == AF_INET) {
        const sockaddr_in& x_sin = reinterpret_cast<const sockaddr_in&>(x);
        const sockaddr_in& y_sin = reinterpret_cast<const sockaddr_in&>(y);
        return make_tie(x_sin) < make_tie(y_sin);
    } else if (x.ss_family == AF_INET6) {
        const sockaddr_in6& x_sin6 = reinterpret_cast<const sockaddr_in6&>(x);
        const sockaddr_in6& y_sin6 = reinterpret_cast<const sockaddr_in6&>(y);
        return make_tie(x_sin6) < make_tie(y_sin6);
    }
    return false;  // Unknown address type.  This is an error.
}

static bool operator ==(const sockaddr_storage& x, const sockaddr_storage& y) {
    if (x.ss_family != y.ss_family) {
        return false;
    }
    // Same address family.
    if (x.ss_family == AF_INET) {
        const sockaddr_in& x_sin = reinterpret_cast<const sockaddr_in&>(x);
        const sockaddr_in& y_sin = reinterpret_cast<const sockaddr_in&>(y);
        return make_tie(x_sin) == make_tie(y_sin);
    } else if (x.ss_family == AF_INET6) {
        const sockaddr_in6& x_sin6 = reinterpret_cast<const sockaddr_in6&>(x);
        const sockaddr_in6& y_sin6 = reinterpret_cast<const sockaddr_in6&>(y);
        return make_tie(x_sin6) == make_tie(y_sin6);
    }
    return false;  // Unknown address type.  This is an error.
}

namespace android {
namespace net {

namespace {

bool setNonBlocking(int fd, bool enabled) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return false;

    if (enabled) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    return (fcntl(fd, F_SETFL, flags) == 0);
}

int waitForReading(int fd) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    const int ret = TEMP_FAILURE_RETRY(select(fd + 1, &fds, nullptr, nullptr, nullptr));
    if (DBG && ret <= 0) {
        ALOGD("select");
    }
    return ret;
}

int waitForWriting(int fd) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    const int ret = TEMP_FAILURE_RETRY(select(fd + 1, nullptr, &fds, nullptr, nullptr));
    if (DBG && ret <= 0) {
        ALOGD("select");
    }
    return ret;
}

}  // namespace

android::base::unique_fd DnsTlsTransport::makeConnectedSocket() const {
    android::base::unique_fd fd;
    int type = SOCK_NONBLOCK | SOCK_CLOEXEC;
    switch (mServer.protocol) {
        case IPPROTO_TCP:
            type |= SOCK_STREAM;
            break;
        default:
            errno = EPROTONOSUPPORT;
            return fd;
    }

    fd.reset(socket(mServer.ss.ss_family, type, mServer.protocol));
    if (fd.get() == -1) {
        return fd;
    }

    const socklen_t len = sizeof(mMark);
    if (setsockopt(fd.get(), SOL_SOCKET, SO_MARK, &mMark, len) == -1) {
        fd.reset();
    } else if (connect(fd.get(),
            reinterpret_cast<const struct sockaddr *>(&mServer.ss), sizeof(mServer.ss)) != 0
        && errno != EINPROGRESS) {
        fd.reset();
    }

    return fd;
}

bool getSPKIDigest(const X509* cert, std::vector<uint8_t>* out) {
    int spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
    unsigned char spki[spki_len];
    unsigned char* temp = spki;
    if (spki_len != i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &temp)) {
        ALOGW("SPKI length mismatch");
        return false;
    }
    out->resize(SHA256_SIZE);
    unsigned int digest_len = 0;
    int ret = EVP_Digest(spki, spki_len, out->data(), &digest_len, EVP_sha256(), NULL);
    if (ret != 1) {
        ALOGW("Server cert digest extraction failed");
        return false;
    }
    if (digest_len != out->size()) {
        ALOGW("Wrong digest length: %d", digest_len);
        return false;
    }
    return true;
}

// This comparison ignores ports and fingerprints.
// TODO: respect IPv6 scope id (e.g. link-local addresses).
bool AddressComparator::operator() (const DnsTlsTransport::Server& x,
        const DnsTlsTransport::Server& y) const {
    if (x.ss.ss_family != y.ss.ss_family) {
        return x.ss.ss_family < y.ss.ss_family;
    }
    // Same address family.
    if (x.ss.ss_family == AF_INET) {
        const sockaddr_in& x_sin = reinterpret_cast<const sockaddr_in&>(x.ss);
        const sockaddr_in& y_sin = reinterpret_cast<const sockaddr_in&>(y.ss);
        return x_sin.sin_addr.s_addr < y_sin.sin_addr.s_addr;
    } else if (x.ss.ss_family == AF_INET6) {
        const sockaddr_in6& x_sin6 = reinterpret_cast<const sockaddr_in6&>(x.ss);
        const sockaddr_in6& y_sin6 = reinterpret_cast<const sockaddr_in6&>(y.ss);
        return x_sin6.sin6_addr < y_sin6.sin6_addr;
    }
    return false;  // Unknown address type.  This is an error.
}

// Returns a tuple of references to the elements of s.
auto make_tie(const DnsTlsTransport::Server& s) {
    return std::tie(
        s.ss,
        s.name,
        s.fingerprints,
        s.protocol
    );
}

bool DnsTlsTransport::Server::operator <(const DnsTlsTransport::Server& other) const {
    return make_tie(*this) < make_tie(other);
}

bool DnsTlsTransport::Server::operator ==(const DnsTlsTransport::Server& other) const {
    return make_tie(*this) == make_tie(other);
}

SSL* DnsTlsTransport::sslConnect(int fd) {
    if (fd < 0) {
        ALOGD("%u makeConnectedSocket() failed with: %s", mMark, strerror(errno));
        return nullptr;
    }

    // Set up TLS context.
    bssl::UniquePtr<SSL_CTX> ssl_ctx(SSL_CTX_new(TLS_method()));
    if (!SSL_CTX_set_max_proto_version(ssl_ctx.get(), TLS1_3_VERSION) ||
        !SSL_CTX_set_min_proto_version(ssl_ctx.get(), TLS1_1_VERSION)) {
        ALOGD("failed to min/max TLS versions");
        return nullptr;
    }

    bssl::UniquePtr<SSL> ssl(SSL_new(ssl_ctx.get()));
    // This file descriptor is owned by a unique_fd, so don't let libssl close it.
    bssl::UniquePtr<BIO> bio(BIO_new_socket(fd, BIO_NOCLOSE));
    SSL_set_bio(ssl.get(), bio.get(), bio.get());
    bio.release();

    if (!setNonBlocking(fd, false)) {
        ALOGE("Failed to disable nonblocking status on DNS-over-TLS fd");
        return nullptr;
    }

    if (!mServer.name.empty()) {
        if (SSL_set_tlsext_host_name(ssl.get(), mServer.name.c_str()) != 1) {
            ALOGE("Failed to set SNI to %s", mServer.name.c_str());
            return nullptr;
        }
        X509_VERIFY_PARAM* param = SSL_get0_param(ssl.get());
        X509_VERIFY_PARAM_set1_host(param, mServer.name.c_str(), 0);
        // This will cause the handshake to fail if certificate verification fails.
        SSL_set_verify(ssl.get(), SSL_VERIFY_PEER, nullptr);
    }

    for (;;) {
        if (DBG) {
            ALOGD("%u Calling SSL_connect", mMark);
        }
        int ret = SSL_connect(ssl.get());
        if (DBG) {
            ALOGD("%u SSL_connect returned %d", mMark, ret);
        }
        if (ret == 1) break;  // SSL handshake complete;

        const int ssl_err = SSL_get_error(ssl.get(), ret);
        switch (ssl_err) {
            case SSL_ERROR_WANT_READ:
                if (waitForReading(fd) != 1) {
                    ALOGW("SSL_connect read error");
                    return nullptr;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if (waitForWriting(fd) != 1) {
                    ALOGW("SSL_connect write error");
                    return nullptr;
                }
                break;
            default:
                ALOGW("SSL_connect error %d, errno=%d", ssl_err, errno);
                return nullptr;
        }
    }

    if (!mServer.fingerprints.empty()) {
        if (DBG) {
            ALOGD("Checking DNS over TLS fingerprint");
        }

        // We only care that the chain is internally self-consistent, not that
        // it chains to a trusted root, so we can ignore some kinds of errors.
        // TODO: Add a CA root verification mode that respects these errors.
        int verify_result = SSL_get_verify_result(ssl.get());
        switch (verify_result) {
            case X509_V_OK:
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            case X509_V_ERR_CERT_UNTRUSTED:
                break;
            default:
                ALOGW("Invalid certificate chain, error %d", verify_result);
                return nullptr;
        }

        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl.get());
        if (!chain) {
            ALOGW("Server has null certificate");
            return nullptr;
        }
        // Chain and its contents are owned by ssl, so we don't need to free explicitly.
        bool matched = false;
        for (size_t i = 0; i < sk_X509_num(chain); ++i) {
            // This appears to be O(N^2), but there doesn't seem to be a straightforward
            // way to walk a STACK_OF nondestructively in linear time.
            X509* cert = sk_X509_value(chain, i);
            std::vector<uint8_t> digest;
            if (!getSPKIDigest(cert, &digest)) {
                ALOGE("Digest computation failed");
                return nullptr;
            }

            if (mServer.fingerprints.count(digest) > 0) {
                matched = true;
                break;
            }
        }

        if (!matched) {
            ALOGW("No matching fingerprint");
            return nullptr;
        }

        if (DBG) {
            ALOGD("DNS over TLS fingerprint is correct");
        }
    }

    if (DBG) {
        ALOGD("%u handshake complete", mMark);
    }
    return ssl.release();
}

bool DnsTlsTransport::sslWrite(int fd, SSL *ssl, const uint8_t *buffer, int len) {
    if (DBG) {
        ALOGD("%u Writing %d bytes", mMark, len);
    }
    for (;;) {
        int ret = SSL_write(ssl, buffer, len);
        if (ret == len) break;  // SSL write complete;

        if (ret < 1) {
            const int ssl_err = SSL_get_error(ssl, ret);
            switch (ssl_err) {
                case SSL_ERROR_WANT_WRITE:
                    if (waitForWriting(fd) != 1) {
                        if (DBG) {
                            ALOGW("SSL_write error");
                        }
                        return false;
                    }
                    continue;
                case 0:
                    break;  // SSL write complete;
                default:
                    if (DBG) {
                        ALOGW("SSL_write error %d", ssl_err);
                    }
                    return false;
            }
        }
    }
    if (DBG) {
        ALOGD("%u Wrote %d bytes", mMark, len);
    }
    return true;
}

// Read exactly len bytes into buffer or fail
bool DnsTlsTransport::sslRead(int fd, SSL *ssl, uint8_t *buffer, int len) {
    int remaining = len;
    while (remaining > 0) {
        int ret = SSL_read(ssl, buffer + (len - remaining), remaining);
        if (ret == 0) {
            ALOGE("SSL socket closed with %i of %i bytes remaining", remaining, len);
            return false;
        }

        if (ret < 0) {
            const int ssl_err = SSL_get_error(ssl, ret);
            if (ssl_err == SSL_ERROR_WANT_READ) {
                if (waitForReading(fd) != 1) {
                    if (DBG) {
                        ALOGW("SSL_read error");
                    }
                    return false;
                }
                continue;
            } else {
                if (DBG) {
                    ALOGW("SSL_read error %d", ssl_err);
                }
                return false;
            }
        }

        remaining -= ret;
    }
    return true;
}

// static
DnsTlsTransport::Response DnsTlsTransport::query(const Server& server, unsigned mark,
        const uint8_t *query, size_t qlen, uint8_t *response, size_t limit, int *resplen) {
    // TODO: Keep a static container of transports instead of constructing a new one
    // for every query.
    DnsTlsTransport xport(server, mark);
    return xport.doQuery(query, qlen, response, limit, resplen);
}

DnsTlsTransport::Response DnsTlsTransport::doQuery(const uint8_t *query, size_t qlen,
        uint8_t *response, size_t limit, int *resplen) {
    *resplen = 0;  // Zero indicates an error.

    if (DBG) {
        ALOGD("%u connecting TCP socket", mMark);
    }
    android::base::unique_fd fd(makeConnectedSocket());
    if (DBG) {
        ALOGD("%u connecting SSL", mMark);
    }
    bssl::UniquePtr<SSL> ssl(sslConnect(fd));
    if (ssl == nullptr) {
        if (DBG) {
            ALOGW("%u SSL connection failed", mMark);
        }
        return Response::network_error;
    }

    uint8_t queryHeader[2];
    queryHeader[0] = qlen >> 8;
    queryHeader[1] = qlen;
    if (!sslWrite(fd.get(), ssl.get(), queryHeader, 2)) {
        return Response::network_error;
    }
    if (!sslWrite(fd.get(), ssl.get(), query, qlen)) {
        return Response::network_error;
    }
    if (DBG) {
        ALOGD("%u SSL_write complete", mMark);
    }

    uint8_t responseHeader[2];
    if (!sslRead(fd.get(), ssl.get(), responseHeader, 2)) {
        if (DBG) {
            ALOGW("%u Failed to read 2-byte length header", mMark);
        }
        return Response::network_error;
    }
    const uint16_t responseSize = (responseHeader[0] << 8) | responseHeader[1];
    if (DBG) {
        ALOGD("%u Expecting response of size %i", mMark, responseSize);
    }
    if (responseSize > limit) {
        ALOGE("%u Response doesn't fit in output buffer: %i", mMark, responseSize);
        return Response::limit_error;
    }
    if (!sslRead(fd.get(), ssl.get(), response, responseSize)) {
        if (DBG) {
            ALOGW("%u Failed to read %i bytes", mMark, responseSize);
        }
        return Response::network_error;
    }
    if (DBG) {
        ALOGD("%u SSL_read complete", mMark);
    }

    if (response[0] != query[0] || response[1] != query[1]) {
        ALOGE("reply query ID != query ID");
        return Response::internal_error;
    }

    SSL_shutdown(ssl.get());

    *resplen = responseSize;
    return Response::success;
}

// static
bool DnsTlsTransport::validate(const Server& server, unsigned netid) {
    if (DBG) {
        ALOGD("Beginning validation on %u", netid);
    }
    // Generate "<random>-dnsotls-ds.metric.gstatic.com", which we will lookup through |ss| in
    // order to prove that it is actually a working DNS over TLS server.
    static const char kDnsSafeChars[] =
            "abcdefhijklmnopqrstuvwxyz"
            "ABCDEFHIJKLMNOPQRSTUVWXYZ"
            "0123456789";
    const auto c = [](uint8_t rnd) -> uint8_t {
        return kDnsSafeChars[(rnd % ARRAY_SIZE(kDnsSafeChars))];
    };
    uint8_t rnd[8];
    arc4random_buf(rnd, ARRAY_SIZE(rnd));
    // We could try to use res_mkquery() here, but it's basically the same.
    uint8_t query[] = {
        rnd[6], rnd[7],  // [0-1]   query ID
        1, 0,  // [2-3]   flags; query[2] = 1 for recursion desired (RD).
        0, 1,  // [4-5]   QDCOUNT (number of queries)
        0, 0,  // [6-7]   ANCOUNT (number of answers)
        0, 0,  // [8-9]   NSCOUNT (number of name server records)
        0, 0,  // [10-11] ARCOUNT (number of additional records)
        17, c(rnd[0]), c(rnd[1]), c(rnd[2]), c(rnd[3]), c(rnd[4]), c(rnd[5]),
            '-', 'd', 'n', 's', 'o', 't', 'l', 's', '-', 'd', 's',
        6, 'm', 'e', 't', 'r', 'i', 'c',
        7, 'g', 's', 't', 'a', 't', 'i', 'c',
        3, 'c', 'o', 'm',
        0,  // null terminator of FQDN (root TLD)
        0, ns_t_aaaa,  // QTYPE
        0, ns_c_in     // QCLASS
    };
    const int qlen = ARRAY_SIZE(query);

    const int kRecvBufSize = 4 * 1024;
    uint8_t recvbuf[kRecvBufSize];

    // At validation time, we only know the netId, so we have to guess/compute the
    // corresponding socket mark.
    Fwmark fwmark;
    fwmark.permission = PERMISSION_SYSTEM;
    fwmark.explicitlySelected = true;
    fwmark.protectedFromVpn = true;
    fwmark.netId = netid;
    unsigned mark = fwmark.intValue;
    int replylen = 0;
    DnsTlsTransport::query(server, mark, query, qlen, recvbuf, kRecvBufSize, &replylen);
    if (replylen == 0) {
        if (DBG) {
            ALOGD("query failed");
        }
        return false;
    }

    if (replylen < NS_HFIXEDSZ) {
        if (DBG) {
            ALOGW("short response: %d", replylen);
        }
        return false;
    }

    const int qdcount = (recvbuf[4] << 8) | recvbuf[5];
    if (qdcount != 1) {
        ALOGW("reply query count != 1: %d", qdcount);
        return false;
    }

    const int ancount = (recvbuf[6] << 8) | recvbuf[7];
    if (DBG) {
        ALOGD("%u answer count: %d", netid, ancount);
    }

    // TODO: Further validate the response contents (check for valid AAAA record, ...).
    // Note that currently, integration tests rely on this function accepting a
    // response with zero records.
#if 0
    for (int i = 0; i < resplen; i++) {
        ALOGD("recvbuf[%d] = %d %c", i, recvbuf[i], recvbuf[i]);
    }
#endif
    return true;
}

}  // namespace net
}  // namespace android
