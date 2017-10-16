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

#include "dns/DnsTlsDispatcher.h"

namespace android {
namespace net {

// static
std::mutex DnsTlsDispatcher::sLock;
std::map<DnsTlsDispatcher::Key, std::unique_ptr<DnsTlsDispatcher::Transport>> DnsTlsDispatcher::sStore;
DnsTlsTransport::Response DnsTlsDispatcher::query(const DnsTlsServer& server, unsigned mark,
        const uint8_t *query, size_t qlen, uint8_t *response, size_t limit, int *resplen) {
    const Key key = std::make_pair(mark, server);
    Transport* xport;
    {
        std::lock_guard<std::mutex> guard(sLock);
        auto it = sStore.find(key);
        if (it == sStore.end()) {
            xport = new Transport(server, mark);
            if (!xport->transport.initialize()) {
                return DnsTlsTransport::Response::internal_error;
            }
            sStore[key].reset(xport);
        } else {
            xport = it->second.get();
        }
        ++xport->useCount;
    }

    DnsTlsTransport::Response res = xport->transport.query(query, qlen, response, limit, resplen);
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> guard(sLock);
        --xport->useCount;
        xport->lastUsed = now;
        cleanup(now);
    }
    return res;
}

static constexpr std::chrono::minutes IDLE_TIMEOUT(5);
std::chrono::time_point<std::chrono::steady_clock> DnsTlsDispatcher::sLastCleanup;
void DnsTlsDispatcher::cleanup(std::chrono::time_point<std::chrono::steady_clock> now) {
    if (now - sLastCleanup < IDLE_TIMEOUT) {
        return;
    }
    for (auto it = sStore.begin(); it != sStore.end(); ) {
        auto& s = it->second;
        if (s->useCount == 0 && now - s->lastUsed > IDLE_TIMEOUT) {
            it = sStore.erase(it);
        } else {
            ++it;
        }
    }
    sLastCleanup = now;
}

}  // namespace net
}  // namespace android
