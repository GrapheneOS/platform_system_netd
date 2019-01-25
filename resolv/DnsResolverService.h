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

#ifndef _DNS_RESOLVER_SERVICE_H_
#define _DNS_RESOLVER_SERVICE_H_

#include <vector>

#include <aidl/android/net/BnDnsResolver.h>
#include <android/binder_ibinder.h>

#include "netd_resolv/resolv.h"

namespace android {
namespace net {

class DnsResolverService : public aidl::android::net::BnDnsResolver {
  public:
    static binder_status_t start();
    static char const* getServiceName() { return "dnsresolver"; }
    // TODO: Add dump() after libbinder_ndk support it.

    ::ndk::ScopedAStatus isAlive(bool* alive) override;
    ::ndk::ScopedAStatus registerEventListener(
            const std::shared_ptr<aidl::android::net::metrics::INetdEventListener>& listener)
            override;

  private:
    DnsResolverService() {}
    // TODO: Remove below items after libbiner_ndk supports check_permission.
    ::ndk::ScopedAStatus checkAnyPermission(const std::vector<const char*>& permissions);
};

}  // namespace net
}  // namespace android

#endif  // _DNS_RESOLVER_SERVICE_H_
