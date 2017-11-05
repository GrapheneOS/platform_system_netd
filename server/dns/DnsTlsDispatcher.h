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

#ifndef _DNS_DNSTLSDISPATCHER_H
#define _DNS_DNSTLSDISPATCHER_H

#include <memory>
#include <map>
#include <mutex>

#include <android-base/thread_annotations.h>

#include "dns/DnsTlsServer.h"
#include "dns/DnsTlsTransport.h"

namespace android {
namespace net {

// This is a totally static class that manages the collection of active DnsTlsTransports.
// Queries made here are dispatched to an existing or newly constructed DnsTlsTransport.
class DnsTlsDispatcher {
public:
    // Given a |query| of length |qlen|, sends it to the server on the network indicated by |mark|,
    // and writes the response into |ans|, which can accept up to |anssiz| bytes.  Indicates
    // the number of bytes written in |resplen|.  If |resplen| is zero, an
    // error has occurred.
    static DnsTlsTransport::Response query(const DnsTlsServer& server, unsigned mark,
            const uint8_t *query, size_t qlen, uint8_t *ans, size_t anssiz, int *resplen);

private:
    static std::mutex sLock;

    typedef std::pair<unsigned, const DnsTlsServer> Key;

    // Transport is a thin wrapper around DnsTlsTransport, adding reference counting and
    // idle monitoring so we can expire unused sessions from the cache.
    struct Transport {
        Transport(const DnsTlsServer& server, unsigned mark) : transport(server, mark) {}
        // DnsTlsSession is thread-safe (internally locked), so it doesn't need to be guarded.
        DnsTlsTransport transport;
        // This use counter and timestamp are used to ensure that only idle sessions are
        // destroyed.
        int useCount GUARDED_BY(sLock) = 0;
        std::chrono::time_point<std::chrono::steady_clock> lastUsed GUARDED_BY(sLock);
    };

    // Cache of reusable DnsTlsTransports.  Transports stay in cache as long as
    // they are in use and for a few minutes after.
    // The key is a (netid, server) pair.  The netid is first for lexicographic comparison speed.
    static std::map<Key, std::unique_ptr<Transport>> sStore GUARDED_BY(sLock);

    // The last time we did a cleanup.  For efficiency, we only perform a cleanup once every
    // few minutes.
    static std::chrono::time_point<std::chrono::steady_clock> sLastCleanup GUARDED_BY(sLock);

    // Drop any cache entries whose useCount is zero and which have not been used recently.
    static void cleanup(std::chrono::time_point<std::chrono::steady_clock> now) REQUIRES(sLock);
};

}  // namespace net
}  // namespace android

#endif  // _DNS_DNSTLSDISPATCHER_H
