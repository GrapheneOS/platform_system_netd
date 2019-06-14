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

#pragma once

#include <arpa/nameser.h>
#include <netdb.h>

#include <string>
#include <vector>

#include <netdutils/InternetAddresses.h>

#include "ResolverStats.h"

#include "android/net/IDnsResolver.h"
#include "dns_responder/dns_responder.h"
#include "netd_resolv/params.h"

// TODO: make this dynamic and stop depending on implementation details.
constexpr int TEST_NETID = 30;

size_t GetNumQueries(const test::DNSResponder& dns, const char* name);
size_t GetNumQueriesForType(const test::DNSResponder& dns, ns_type type, const char* name);
std::string ToString(const hostent* he);
std::string ToString(const addrinfo* ai);
std::string ToString(const android::netdutils::ScopedAddrinfo& ai);
std::vector<std::string> ToStrings(const addrinfo* ai);
std::vector<std::string> ToStrings(const android::netdutils::ScopedAddrinfo& ai);

bool GetResolverInfo(android::net::IDnsResolver* dnsResolverService, unsigned netId,
                     std::vector<std::string>* servers, std::vector<std::string>* domains,
                     std::vector<std::string>* tlsServers, res_params* params,
                     std::vector<android::net::ResolverStats>* stats,
                     int* wait_for_pending_req_timeout_count);
