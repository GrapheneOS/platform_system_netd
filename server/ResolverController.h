/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef _RESOLVER_CONTROLLER_H_
#define _RESOLVER_CONTROLLER_H_

#include <vector>

struct __res_params;
struct sockaddr_storage;

namespace android {
namespace net {

struct DnsTlsServer;
class DumpWriter;
struct ResolverStats;

class ResolverController {
public:
    ResolverController() {};

    virtual ~ResolverController() {};

    // TODO: delete this function
    int setDnsServers(unsigned netId, const char* searchDomains, const char** servers,
            int numservers, const __res_params* params);

    // Validation status of a DNS over TLS server (on a specific netId).
    enum class Validation : uint8_t { in_process, success, fail, unknown_server, unknown_netid };

    // Given a netId and the address of an insecure (i.e. normal) DNS server, this method checks
    // if there is a known secure DNS server with the same IP address that has been validated as
    // accessible on this netId.  It returns the validation status, and provides the secure server
    // (including port, name, and fingerprints) in the output parameter.
    Validation getTlsStatus(unsigned netId, const sockaddr_storage& insecureServer,
            DnsTlsServer* secureServer);

    int clearDnsServers(unsigned netid);

    int flushDnsCache(unsigned netid);

    int getDnsInfo(unsigned netId, std::vector<std::string>* servers,
            std::vector<std::string>* domains, __res_params* params,
            std::vector<android::net::ResolverStats>* stats);

    // Binder specific functions, which convert between the binder int/string arrays and the
    // actual data structures, and call setDnsServer() / getDnsInfo() for the actual processing.
    int setResolverConfiguration(int32_t netId, const std::vector<std::string>& servers,
            const std::vector<std::string>& domains, const std::vector<int32_t>& params,
            bool useTls, const std::string& tlsName,
            const std::set<std::vector<uint8_t>>& tlsFingerprints);

    int getResolverInfo(int32_t netId, std::vector<std::string>* servers,
            std::vector<std::string>* domains, std::vector<int32_t>* params,
            std::vector<int32_t>* stats);
    void dump(DumpWriter& dw, unsigned netId);

};

}  // namespace net
}  // namespace android

#endif /* _RESOLVER_CONTROLLER_H_ */
