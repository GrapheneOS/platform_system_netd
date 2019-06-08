/**
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dns_metrics_listener.h"

#include <android-base/chrono_utils.h>
#include <thread>

namespace android {
namespace net {
namespace metrics {

using std::chrono::milliseconds;

constexpr milliseconds kRetryIntervalMs{20};

android::binder::Status DnsMetricsListener::onNat64PrefixEvent(int32_t netId, bool added,
                                                               const std::string& prefixString,
                                                               int32_t /*prefixLength*/) {
    std::lock_guard lock(mMutex);
    if (netId == mNetId) mNat64Prefix = added ? prefixString : "";
    return android::binder::Status::ok();
}

bool DnsMetricsListener::waitForNat64Prefix(ExpectNat64PrefixStatus status,
                                            milliseconds timeout) const {
    android::base::Timer t;
    while (t.duration() < timeout) {
        {
            std::lock_guard lock(mMutex);
            if ((status == EXPECT_FOUND && !mNat64Prefix.empty()) ||
                (status == EXPECT_NOT_FOUND && mNat64Prefix.empty()))
                return true;
        }
        std::this_thread::sleep_for(kRetryIntervalMs);
    }
    return false;
}

}  // namespace metrics
}  // namespace net
}  // namespace android