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

#define LOG_TAG "DnsTlsTransport"

#include "dns/DnsTlsTransport.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include "dns/DnsTlsServer.h"
#include "dns/DnsTlsSocketFactory.h"
#include "dns/IDnsTlsSocketFactory.h"

//#define LOG_NDEBUG 0

#include "log/log.h"
#include "Fwmark.h"
#undef ADD  // already defined in nameser.h
#include "NetdConstants.h"
#include "Permission.h"

namespace android {
namespace net {

DnsTlsTransport::Result DnsTlsTransport::query(const netdutils::Slice query) {
    if (query.size() < 2) {
        return (Result) { .code = Response::internal_error };
    }

    const uint8_t* data = query.base();
    uint16_t id = data[0] << 8 | data[1];

    auto socket = mFactory->createDnsTlsSocket(mServer, mMark, &mCache);
    if (!socket) {
        return (Result) { .code = Response::network_error };
    }

    return socket->query(id, netdutils::drop(query, 2));
}

DnsTlsTransport::~DnsTlsTransport() {
}

// static
// TODO: Use this function to preheat the session cache.
// That may require moving it to DnsTlsDispatcher.
bool DnsTlsTransport::validate(const DnsTlsServer& server, unsigned netid) {
    ALOGV("Beginning validation on %u", netid);
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

    // At validation time, we only know the netId, so we have to guess/compute the
    // corresponding socket mark.
    Fwmark fwmark;
    fwmark.permission = PERMISSION_SYSTEM;
    fwmark.explicitlySelected = true;
    fwmark.protectedFromVpn = true;
    fwmark.netId = netid;
    unsigned mark = fwmark.intValue;
    int replylen = 0;
    DnsTlsSocketFactory factory;
    DnsTlsTransport transport(server, mark, &factory);
    auto r = transport.query(Slice(query, qlen));
    if (r.code != Response::success) {
        ALOGV("query failed");
        return false;
    }

    const std::vector<uint8_t>& recvbuf = r.response;
    if (recvbuf.size() < NS_HFIXEDSZ) {
        ALOGW("short response: %d", replylen);
        return false;
    }

    const int qdcount = (recvbuf[4] << 8) | recvbuf[5];
    if (qdcount != 1) {
        ALOGW("reply query count != 1: %d", qdcount);
        return false;
    }

    const int ancount = (recvbuf[6] << 8) | recvbuf[7];
    ALOGV("%u answer count: %d", netid, ancount);

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

}  // end of namespace net
}  // end of namespace android
