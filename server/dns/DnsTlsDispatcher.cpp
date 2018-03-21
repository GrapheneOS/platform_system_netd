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

#define LOG_TAG "DnsTlsDispatcher"
//#define LOG_NDEBUG 0

#include "dns/DnsTlsDispatcher.h"

#include "log/log.h"

namespace android {
namespace net {

using netdutils::Slice;

// static
std::mutex DnsTlsDispatcher::sLock;
DnsTlsTransport::Response DnsTlsDispatcher::query(const DnsTlsServer& server, unsigned mark,
                                                  const Slice query,
                                                  const Slice ans, int *resplen) {
    const Key key = std::make_pair(mark, server);
    Transport* xport;
    {
        std::lock_guard<std::mutex> guard(sLock);
        auto it = mStore.find(key);
        if (it == mStore.end()) {
            xport = new Transport(server, mark, mFactory.get());
            mStore[key].reset(xport);
        } else {
            xport = it->second.get();
        }
        ++xport->useCount;
    }

    ALOGV("Sending query of length %zu", query.size());
    auto res = xport->transport.query(query);
    ALOGV("Awaiting response");
    const auto& result = res.get();
    DnsTlsTransport::Response code = result.code;
    if (code == DnsTlsTransport::Response::success) {
        if (result.response.size() > ans.size()) {
            ALOGV("Response too large: %zu > %zu", result.response.size(), ans.size());
            code = DnsTlsTransport::Response::limit_error;
        } else {
            ALOGV("Got response successfully");
            *resplen = result.response.size();
            netdutils::copy(ans, netdutils::makeSlice(result.response));
        }
    } else {
        ALOGV("Query failed: %u", (unsigned int)code);
    }

    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> guard(sLock);
        --xport->useCount;
        xport->lastUsed = now;
        cleanup(now);
    }
    return code;
}

// This timeout effectively controls how long to keep SSL session tickets.
static constexpr std::chrono::minutes IDLE_TIMEOUT(5);
void DnsTlsDispatcher::cleanup(std::chrono::time_point<std::chrono::steady_clock> now) {
    // To avoid scanning mStore after every query, return early if a cleanup has been
    // performed recently.
    if (now - mLastCleanup < IDLE_TIMEOUT) {
        return;
    }
    for (auto it = mStore.begin(); it != mStore.end();) {
        auto& s = it->second;
        if (s->useCount == 0 && now - s->lastUsed > IDLE_TIMEOUT) {
            it = mStore.erase(it);
        } else {
            ++it;
        }
    }
    mLastCleanup = now;
}

}  // end of namespace net
}  // end of namespace android
