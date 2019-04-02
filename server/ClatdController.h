/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _CLATD_CONTROLLER_H
#define _CLATD_CONTROLLER_H

#include <map>
#include <mutex>
#include <string>

#include <linux/if.h>
#include <netinet/in.h>

#include <android-base/thread_annotations.h>

#include "Fwmark.h"
#include "NetdConstants.h"
#include "bpf/BpfMap.h"
#include "netdbpf/bpf_shared.h"
#include "netdutils/DumpWriter.h"

namespace android {
namespace net {

class NetworkController;

class ClatdController {
  public:
    explicit ClatdController(NetworkController* controller);
    virtual ~ClatdController();

    void Init(void);

    int startClatd(const std::string& interface, const std::string& nat64Prefix,
                   std::string* v6Addr);
    int stopClatd(const std::string& interface);

    void dump(netdutils::DumpWriter& dw) EXCLUDES(mutex);

    std::mutex mutex;

  private:
    struct ClatdTracker {
        const NetworkController* netCtrl = nullptr;
        pid_t pid = -1;
        unsigned ifIndex;
        char iface[IFNAMSIZ];
        Fwmark fwmark;
        char fwmarkString[UINT32_STRLEN];
        unsigned netId;
        char netIdString[UINT32_STRLEN];
        in_addr v4;
        char v4Str[INET_ADDRSTRLEN];
        in6_addr v6;
        char v6Str[INET6_ADDRSTRLEN];
        in6_addr pfx96;
        char pfx96String[INET6_ADDRSTRLEN];

        ClatdTracker() = default;
        explicit ClatdTracker(const NetworkController* netCtrl) : netCtrl(netCtrl) {}

        int init(const std::string& interface, const std::string& nat64Prefix);
    };

    const NetworkController* mNetCtrl;
    std::map<std::string, ClatdTracker> mClatdTrackers;
    ClatdTracker* getClatdTracker(const std::string& interface);

    static in_addr_t selectIpv4Address(const in_addr ip, int16_t prefixlen);
    static int generateIpv6Address(const char* iface, const in_addr v4, const in6_addr& nat64Prefix,
                                   in6_addr* v6);
    static void makeChecksumNeutral(in6_addr* v6, const in_addr v4, const in6_addr& nat64Prefix);

    enum eClatEbpfMode {
        ClatEbpfDisabled,  //  <4.9 kernel ||  <P api shipping level -- will not work
        ClatEbpfMaybe,     // >=4.9 kernel &&   P api shipping level -- might work
        ClatEbpfEnabled,   // >=4.9 kernel && >=Q api shipping level -- must work
    };
    eClatEbpfMode mClatEbpfMode;
    base::unique_fd mNetlinkFd;
    bpf::BpfMap<ClatIngressKey, ClatIngressValue> mClatIngressMap;

    void maybeStartBpf(const ClatdTracker& tracker);
    void maybeStopBpf(const ClatdTracker& tracker);

    // For testing.
    friend class ClatdControllerTest;

    static bool (*isIpv4AddressFreeFunc)(in_addr_t);
    static bool isIpv4AddressFree(in_addr_t addr);
};

}  // namespace net
}  // namespace android

#endif
