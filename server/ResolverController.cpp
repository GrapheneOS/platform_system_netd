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

#define LOG_TAG "ResolverController"
#define DBG 0

#include <algorithm>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <log/log.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>

#include <android-base/strings.h>
#include <android-base/thread_annotations.h>
#include <android/net/INetd.h>
#include <android/net/metrics/INetdEventListener.h>

#include "Controllers.h"
#include "DumpWriter.h"
#include "EventReporter.h"
#include "Fwmark.h"
#include "NetdConstants.h"
#include "Permission.h"
#include "ResolverController.h"
#include "ResolverStats.h"
#include "netd_resolv/params.h"
#include "netd_resolv/resolv.h"
#include "netd_resolv/resolv_stub.h"
#include "netd_resolv/stats.h"

namespace android {
namespace net {

namespace {

std::string addrToString(const sockaddr_storage* addr) {
    char out[INET6_ADDRSTRLEN] = {0};
    getnameinfo((const sockaddr*)addr, sizeof(sockaddr_storage), out,
            INET6_ADDRSTRLEN, nullptr, 0, NI_NUMERICHOST);
    return std::string(out);
}

const char* getPrivateDnsModeString(PrivateDnsMode mode) {
    switch (mode) {
        case PrivateDnsMode::OFF:
            return "OFF";
        case PrivateDnsMode::OPPORTUNISTIC:
            return "OPPORTUNISTIC";
        case PrivateDnsMode::STRICT:
            return "STRICT";
    }
}

constexpr const char* validationStatusToString(Validation value) {
    switch (value) {
        case Validation::in_process:
            return "in_process";
        case Validation::success:
            return "success";
        case Validation::fail:
            return "fail";
        case Validation::unknown_server:
            return "unknown_server";
        case Validation::unknown_netid:
            return "unknown_netid";
        default:
            return "unknown_status";
    }
}

void onPrivateDnsValidation(unsigned netId, const char* server, const char* hostname,
                            bool success) {
    // Send a validation event to NetdEventListenerService.
    const auto netdEventListener = net::gCtls->eventReporter.getNetdEventListener();
    if (netdEventListener != nullptr) {
        netdEventListener->onPrivateDnsValidationEvent(netId, android::String16(server),
                                                       android::String16(hostname), success);
        if (DBG) {
            ALOGD("Sending validation %s event on netId %u for %s with hostname %s",
                  success ? "success" : "failure", netId, server, hostname);
        }

    } else {
        ALOGE("Validation event not sent since NetdEventListenerService is unavailable.");
    }
}

bool allIPv6Only(const std::vector<std::string>& servers) {
    for (const auto& server : servers) {
        if (server.find(':') == std::string::npos) return false;
    }
    return !servers.empty();
}

}  // namespace

int ResolverController::setDnsServers(unsigned netId, const char* searchDomains,
        const char** servers, int numservers, const __res_params* params) {
    if (DBG) {
        ALOGD("setDnsServers netId = %u, numservers = %d", netId, numservers);
    }
    return -RESOLV_STUB.resolv_set_nameservers_for_net(netId, servers, numservers, searchDomains,
                                                       params);
}

int ResolverController::clearDnsServers(unsigned netId) {
    RESOLV_STUB.resolv_set_nameservers_for_net(netId, nullptr, 0, "", nullptr);
    if (DBG) {
        ALOGD("clearDnsServers netId = %u\n", netId);
    }
    mDns64Configuration.stopPrefixDiscovery(netId);
    RESOLV_STUB.resolv_delete_private_dns_for_net(netId);
    return 0;
}

int ResolverController::getDnsInfo(unsigned netId, std::vector<std::string>* servers,
        std::vector<std::string>* domains, __res_params* params,
        std::vector<android::net::ResolverStats>* stats) {
    using android::net::ResolverStats;
    using android::net::INetd;
    static_assert(ResolverStats::STATS_SUCCESSES == INetd::RESOLVER_STATS_SUCCESSES &&
            ResolverStats::STATS_ERRORS == INetd::RESOLVER_STATS_ERRORS &&
            ResolverStats::STATS_TIMEOUTS == INetd::RESOLVER_STATS_TIMEOUTS &&
            ResolverStats::STATS_INTERNAL_ERRORS == INetd::RESOLVER_STATS_INTERNAL_ERRORS &&
            ResolverStats::STATS_RTT_AVG == INetd::RESOLVER_STATS_RTT_AVG &&
            ResolverStats::STATS_LAST_SAMPLE_TIME == INetd::RESOLVER_STATS_LAST_SAMPLE_TIME &&
            ResolverStats::STATS_USABLE == INetd::RESOLVER_STATS_USABLE &&
            ResolverStats::STATS_COUNT == INetd::RESOLVER_STATS_COUNT,
            "AIDL and ResolverStats.h out of sync");
    int nscount = -1;
    sockaddr_storage res_servers[MAXNS];
    int dcount = -1;
    char res_domains[MAXDNSRCH][MAXDNSRCHPATH];
    res_stats res_stats[MAXNS];
    servers->clear();
    domains->clear();
    *params = __res_params{};
    stats->clear();
    int revision_id = RESOLV_STUB.android_net_res_stats_get_info_for_net(
            netId, &nscount, res_servers, &dcount, res_domains, params, res_stats);

    // If the netId is unknown (which can happen for valid net IDs for which no DNS servers have
    // yet been configured), there is no revision ID. In this case there is no data to return.
    if (revision_id < 0) {
        return 0;
    }

    // Verify that the returned data is sane.
    if (nscount < 0 || nscount > MAXNS || dcount < 0 || dcount > MAXDNSRCH) {
        ALOGE("%s: nscount=%d, dcount=%d", __FUNCTION__, nscount, dcount);
        return -ENOTRECOVERABLE;
    }

    // Determine which servers are considered usable by the resolver.
    bool valid_servers[MAXNS];
    std::fill_n(valid_servers, MAXNS, false);
    RESOLV_STUB.android_net_res_stats_get_usable_servers(params, res_stats, nscount, valid_servers);

    // Convert the server sockaddr structures to std::string.
    stats->resize(nscount);
    for (int i = 0 ; i < nscount ; ++i) {
        char hbuf[NI_MAXHOST];
        int rv = getnameinfo(reinterpret_cast<const sockaddr*>(&res_servers[i]),
                sizeof(res_servers[i]), hbuf, sizeof(hbuf), nullptr, 0, NI_NUMERICHOST);
        std::string server_str;
        if (rv == 0) {
            server_str.assign(hbuf);
        } else {
            ALOGE("getnameinfo() failed for server #%d: %s", i, gai_strerror(rv));
            server_str.assign("<invalid>");
        }
        servers->push_back(std::move(server_str));
        android::net::ResolverStats& cur_stats = (*stats)[i];
        RESOLV_STUB.android_net_res_stats_aggregate(
                &res_stats[i], &cur_stats.successes, &cur_stats.errors, &cur_stats.timeouts,
                &cur_stats.internal_errors, &cur_stats.rtt_avg, &cur_stats.last_sample_time);
        cur_stats.usable = valid_servers[i];
    }

    // Convert the stack-allocated search domain strings to std::string.
    for (int i = 0 ; i < dcount ; ++i) {
        domains->push_back(res_domains[i]);
    }
    return 0;
}

int ResolverController::setResolverConfiguration(int32_t netId,
        const std::vector<std::string>& servers, const std::vector<std::string>& domains,
        const std::vector<int32_t>& params, const std::string& tlsName,
        const std::vector<std::string>& tlsServers,
        const std::set<std::vector<uint8_t>>& tlsFingerprints) {
    using android::net::INetd;
    // TODO: make RESOLVER_PARAMS_BASE_TIMEOUT_MSEC a mandatory parameter once all callers
    //       have been updated to specify it.
    if (params.size() < INetd::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC ||
        params.size() > INetd::RESOLVER_PARAMS_COUNT) {
        ALOGE("%s: params.size()=%zu", __FUNCTION__, params.size());
        return -EINVAL;
    }

    std::vector<const char*> server_ptrs;
    size_t count = std::min<size_t>(MAXNS, tlsServers.size());
    server_ptrs.reserve(count);
    for (size_t i = 0; i < count; i++) {
        server_ptrs.push_back(tlsServers[i].data());
    }

    std::vector<const uint8_t*> fingerprint_ptrs;
    count = tlsFingerprints.size();
    fingerprint_ptrs.reserve(count);
    for (const auto& fp : tlsFingerprints) {
        fingerprint_ptrs.push_back(fp.data());
    }

    // At private DNS validation time, we only know the netId, so we have to guess/compute the
    // corresponding socket mark.
    Fwmark fwmark;
    fwmark.netId = netId;
    fwmark.explicitlySelected = true;
    fwmark.protectedFromVpn = true;
    fwmark.permission = PERMISSION_SYSTEM;

    const int err = RESOLV_STUB.resolv_set_private_dns_for_net(
            netId, fwmark.intValue, server_ptrs.data(), server_ptrs.size(), tlsName.c_str(),
            fingerprint_ptrs.data(), fingerprint_ptrs.size());
    if (err != 0) {
        return err;
    }
    RESOLV_STUB.resolv_register_private_dns_callback(&onPrivateDnsValidation);

    // Convert network-assigned server list to bionic's format.
    server_ptrs.clear();
    count = std::min<size_t>(MAXNS, servers.size());
    server_ptrs.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        server_ptrs.push_back(servers[i].c_str());
    }

    std::string domains_str;
    if (!domains.empty()) {
        domains_str = domains[0];
        count = std::min<size_t>(MAXDNSRCH, domains.size());
        for (size_t i = 1; i < count; ++i) {
            domains_str += " " + domains[i];
        }
    }

    __res_params res_params = {};
    res_params.sample_validity = params[INetd::RESOLVER_PARAMS_SAMPLE_VALIDITY];
    res_params.success_threshold = params[INetd::RESOLVER_PARAMS_SUCCESS_THRESHOLD];
    res_params.min_samples = params[INetd::RESOLVER_PARAMS_MIN_SAMPLES];
    res_params.max_samples = params[INetd::RESOLVER_PARAMS_MAX_SAMPLES];
    if (params.size() > INetd::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC) {
        res_params.base_timeout_msec = params[INetd::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC];
    }

    const auto rval = setDnsServers(netId, domains_str.c_str(), server_ptrs.data(),
                                    server_ptrs.size(), &res_params);

    if (rval == 0) {
        // Start DNS64 discovery after successfully setting any new DNS servers
        // as the cache may have been cleared (if the nameservers differ), and
        // we might discover a different DNS64 prefix. If the cache has not been
        // cleared, we may quickly rediscover the same prefix.
        //
        // Operators may choose to use a longer TTL in order to reduce repeated
        // resolution (see also https://tools.ietf.org/html/rfc7050#section-5).
        if (allIPv6Only(servers)) {
            // TODO: Keep any existing discovered prefix around for use while
            // re-discovery is in progress. Otherwise, whenever DNS servers are
            // pushed to netd there can be gaps where it would appear there was
            // no prefix64 when in fact we had previously discovered one (and
            // are highly likely to rediscover the same one).
            mDns64Configuration.startPrefixDiscovery(netId);
        } else {
            mDns64Configuration.stopPrefixDiscovery(netId);
        }
    }

    return rval;
}

int ResolverController::getResolverInfo(int32_t netId, std::vector<std::string>* servers,
                                        std::vector<std::string>* domains,
                                        std::vector<std::string>* tlsServers,
                                        std::vector<int32_t>* params, std::vector<int32_t>* stats) {
    using android::net::ResolverStats;
    using android::net::INetd;
    __res_params res_params;
    std::vector<ResolverStats> res_stats;
    int ret = getDnsInfo(netId, servers, domains, &res_params, &res_stats);
    if (ret != 0) {
        return ret;
    }

    // Serialize the information for binder.
    ResolverStats::encodeAll(res_stats, stats);

    ExternalPrivateDnsStatus privateDnsStatus = {PrivateDnsMode::OFF, 0, {}};
    RESOLV_STUB.resolv_get_private_dns_status_for_net(netId, &privateDnsStatus);
    for (int i = 0; i < privateDnsStatus.numServers; i++) {
        std::string tlsServer_str = addrToString(&(privateDnsStatus.serverStatus[i].ss));
        tlsServers->push_back(std::move(tlsServer_str));
    }

    params->resize(INetd::RESOLVER_PARAMS_COUNT);
    (*params)[INetd::RESOLVER_PARAMS_SAMPLE_VALIDITY] = res_params.sample_validity;
    (*params)[INetd::RESOLVER_PARAMS_SUCCESS_THRESHOLD] = res_params.success_threshold;
    (*params)[INetd::RESOLVER_PARAMS_MIN_SAMPLES] = res_params.min_samples;
    (*params)[INetd::RESOLVER_PARAMS_MAX_SAMPLES] = res_params.max_samples;
    (*params)[INetd::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC] = res_params.base_timeout_msec;
    return 0;
}

// TODO: use StatusOr<T> to wrap the result.
int ResolverController::getPrefix64(unsigned netId, netdutils::IPPrefix* prefix) {
    netdutils::IPPrefix p = mDns64Configuration.getPrefix64(netId);
    if (p.family() != AF_INET6 || p.length() == 0) {
        ALOGE("No valid NAT64 prefix (%d,%s)\n", netId, p.toString().c_str());
        return -ENOENT;
    }
    *prefix = p;
    return 0;
}

void ResolverController::sendNat64PrefixEvent(const Dns64Configuration::Nat64PrefixInfo& args) {
    const auto netdEventListener = net::gCtls->eventReporter.getNetdEventListener();
    if (netdEventListener == nullptr) {
        gLog.error("getNetdEventListener() returned nullptr. dropping NAT64 prefix event");
        return;
    }
    netdEventListener->onNat64PrefixEvent(args.netId, args.added, args.prefixString,
                                          args.prefixLength);
}

void ResolverController::dump(DumpWriter& dw, unsigned netId) {
    // No lock needed since Bionic's resolver locks all accessed data structures internally.
    using android::net::ResolverStats;
    std::vector<std::string> servers;
    std::vector<std::string> domains;
    __res_params params = {};
    std::vector<ResolverStats> stats;
    time_t now = time(nullptr);
    int rv = getDnsInfo(netId, &servers, &domains, &params, &stats);
    dw.incIndent();
    if (rv != 0) {
        dw.println("getDnsInfo() failed for netid %u", netId);
    } else {
        if (servers.empty()) {
            dw.println("No DNS servers defined");
        } else {
            dw.println("DNS servers: # IP (total, successes, errors, timeouts, internal errors, "
                    "RTT avg, last sample)");
            dw.incIndent();
            for (size_t i = 0 ; i < servers.size() ; ++i) {
                if (i < stats.size()) {
                    const ResolverStats& s = stats[i];
                    int total = s.successes + s.errors + s.timeouts + s.internal_errors;
                    if (total > 0) {
                        int time_delta = (s.last_sample_time > 0) ? now - s.last_sample_time : -1;
                        dw.println("%s (%d, %d, %d, %d, %d, %dms, %ds)%s", servers[i].c_str(),
                                total, s.successes, s.errors, s.timeouts, s.internal_errors,
                                s.rtt_avg, time_delta, s.usable ? "" : " BROKEN");
                    } else {
                        dw.println("%s <no data>", servers[i].c_str());
                    }
                } else {
                    dw.println("%s <no stats>", servers[i].c_str());
                }
            }
            dw.decIndent();
        }
        if (domains.empty()) {
            dw.println("No search domains defined");
        } else {
            std::string domains_str = android::base::Join(domains, ", ");
            dw.println("search domains: %s", domains_str.c_str());
        }
        if (params.sample_validity != 0) {
            dw.println(
                    "DNS parameters: sample validity = %us, success threshold = %u%%, "
                    "samples (min, max) = (%u, %u), base_timeout = %dmsec",
                    params.sample_validity, static_cast<unsigned>(params.success_threshold),
                    static_cast<unsigned>(params.min_samples),
                    static_cast<unsigned>(params.max_samples), params.base_timeout_msec);
        }

        mDns64Configuration.dump(dw, netId);
        ExternalPrivateDnsStatus privateDnsStatus = {PrivateDnsMode::OFF, 0, {}};
        RESOLV_STUB.resolv_get_private_dns_status_for_net(netId, &privateDnsStatus);
        dw.println("Private DNS mode: %s",
                   getPrivateDnsModeString(static_cast<PrivateDnsMode>(privateDnsStatus.mode)));
        if (!privateDnsStatus.numServers) {
            dw.println("No Private DNS servers configured");
        } else {
            dw.println("Private DNS configuration (%u entries)", privateDnsStatus.numServers);
            dw.incIndent();
            for (int i = 0; i < privateDnsStatus.numServers; i++) {
                dw.println("%s name{%s} status{%s}",
                           addrToString(&(privateDnsStatus.serverStatus[i].ss)).c_str(),
                           privateDnsStatus.serverStatus[i].hostname,
                           validationStatusToString(static_cast<Validation>(
                                   privateDnsStatus.serverStatus[i].validation)));
            }
            dw.decIndent();
        }
    }
    dw.decIndent();
}

}  // namespace net
}  // namespace android
