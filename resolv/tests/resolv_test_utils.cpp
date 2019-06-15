/*
 * Copyright (C) 2019 The Android Open Source Project
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
 *
 */

#include "resolv_test_utils.h"

#include <arpa/inet.h>

#include <netdutils/InternetAddresses.h>

using android::net::ResolverStats;
using android::netdutils::ScopedAddrinfo;

std::string ToString(const hostent* he) {
    if (he == nullptr) return "<null>";
    char buffer[INET6_ADDRSTRLEN];
    if (!inet_ntop(he->h_addrtype, he->h_addr_list[0], buffer, sizeof(buffer))) {
        return "<invalid>";
    }
    return buffer;
}

std::string ToString(const addrinfo* ai) {
    if (!ai) return "<null>";
    for (const auto* aip = ai; aip != nullptr; aip = aip->ai_next) {
        char host[NI_MAXHOST];
        int rv = getnameinfo(aip->ai_addr, aip->ai_addrlen, host, sizeof(host), nullptr, 0,
                             NI_NUMERICHOST);
        if (rv != 0) return gai_strerror(rv);
        return host;
    }
    return "<invalid>";
}

std::string ToString(const ScopedAddrinfo& ai) {
    return ToString(ai.get());
}

std::vector<std::string> ToStrings(const addrinfo* ai) {
    std::vector<std::string> hosts;
    if (!ai) {
        hosts.push_back("<null>");
        return hosts;
    }
    for (const auto* aip = ai; aip != nullptr; aip = aip->ai_next) {
        char host[NI_MAXHOST];
        int rv = getnameinfo(aip->ai_addr, aip->ai_addrlen, host, sizeof(host), nullptr, 0,
                             NI_NUMERICHOST);
        if (rv != 0) {
            hosts.clear();
            hosts.push_back(gai_strerror(rv));
            return hosts;
        } else {
            hosts.push_back(host);
        }
    }
    if (hosts.empty()) hosts.push_back("<invalid>");
    return hosts;
}

std::vector<std::string> ToStrings(const ScopedAddrinfo& ai) {
    return ToStrings(ai.get());
}

size_t GetNumQueries(const test::DNSResponder& dns, const char* name) {
    auto queries = dns.queries();
    size_t found = 0;
    for (const auto& p : queries) {
        if (p.first == name) {
            ++found;
        }
    }
    return found;
}

size_t GetNumQueriesForType(const test::DNSResponder& dns, ns_type type, const char* name) {
    auto queries = dns.queries();
    size_t found = 0;
    for (const auto& p : queries) {
        if (p.second == type && p.first == name) {
            ++found;
        }
    }
    return found;
}

bool GetResolverInfo(android::net::IDnsResolver* dnsResolverService, unsigned netId,
                     std::vector<std::string>* servers, std::vector<std::string>* domains,
                     std::vector<std::string>* tlsServers, res_params* params,
                     std::vector<ResolverStats>* stats, int* wait_for_pending_req_timeout_count) {
    using android::net::IDnsResolver;
    std::vector<int32_t> params32;
    std::vector<int32_t> stats32;
    std::vector<int32_t> wait_for_pending_req_timeout_count32{0};
    auto rv = dnsResolverService->getResolverInfo(netId, servers, domains, tlsServers, &params32,
                                                  &stats32, &wait_for_pending_req_timeout_count32);

    if (!rv.isOk() || params32.size() != static_cast<size_t>(IDnsResolver::RESOLVER_PARAMS_COUNT)) {
        return false;
    }
    *params = res_params{
            .sample_validity =
                    static_cast<uint16_t>(params32[IDnsResolver::RESOLVER_PARAMS_SAMPLE_VALIDITY]),
            .success_threshold =
                    static_cast<uint8_t>(params32[IDnsResolver::RESOLVER_PARAMS_SUCCESS_THRESHOLD]),
            .min_samples =
                    static_cast<uint8_t>(params32[IDnsResolver::RESOLVER_PARAMS_MIN_SAMPLES]),
            .max_samples =
                    static_cast<uint8_t>(params32[IDnsResolver::RESOLVER_PARAMS_MAX_SAMPLES]),
            .base_timeout_msec = params32[IDnsResolver::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC],
            .retry_count = params32[IDnsResolver::RESOLVER_PARAMS_RETRY_COUNT],
    };
    *wait_for_pending_req_timeout_count = wait_for_pending_req_timeout_count32[0];
    return ResolverStats::decodeAll(stats32, stats);
}