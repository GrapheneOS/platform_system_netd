/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless requied by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <iterator>
#include <numeric>
#include <thread>

#include <android-base/stringprintf.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

#include <openssl/base64.h>

#define LOG_TAG "netd_test"
// TODO: make this dynamic and stop depending on implementation details.
#define TEST_NETID 30

#include "resolv_netid.h"  // NETID_UNSET
#include "NetdClient.h"

#include <gtest/gtest.h>

#include <utils/Log.h>

#include "dns_responder.h"
#include "dns_responder_client.h"
#include "dns_tls_frontend.h"
#include "resolv_params.h"

#include "NetdConstants.h"
#include "ResolverStats.h"

#include "android/net/INetd.h"
#include "android/net/metrics/INetdEventListener.h"
#include "binder/IServiceManager.h"
#include "netdutils/SocketOption.h"

using android::base::StringPrintf;
using android::net::ResolverStats;
using android::net::metrics::INetdEventListener;
using android::netdutils::enableSockopt;

// TODO: move into libnetdutils?
namespace {
ScopedAddrinfo safe_getaddrinfo(const char* node, const char* service,
                                const struct addrinfo* hints) {
    addrinfo* result = nullptr;
    if (getaddrinfo(node, service, hints, &result) != 0) {
        result = nullptr;  // Should already be the case, but...
    }
    return ScopedAddrinfo(result);
}
}  // namespace

// Emulates the behavior of UnorderedElementsAreArray, which currently cannot be used.
// TODO: Use UnorderedElementsAreArray, which depends on being able to compile libgmock_host,
// if that is not possible, improve this hacky algorithm, which is O(n**2)
template <class A, class B>
bool UnorderedCompareArray(const A& a, const B& b) {
    if (a.size() != b.size()) return false;
    for (const auto& a_elem : a) {
        size_t a_count = 0;
        for (const auto& a_elem2 : a) {
            if (a_elem == a_elem2) {
                ++a_count;
            }
        }
        size_t b_count = 0;
        for (const auto& b_elem : b) {
            if (a_elem == b_elem) ++b_count;
        }
        if (a_count != b_count) return false;
    }
    return true;
}

class ResolverTest : public ::testing::Test, public DnsResponderClient {
  protected:
    void SetUp() {
        // Ensure resolutions go via proxy.
        DnsResponderClient::SetUp();

        // If DNS reporting is off: turn it on so we run through everything.
        auto rv = mNetdSrv->getMetricsReportingLevel(&mOriginalMetricsLevel);
        ASSERT_TRUE(rv.isOk());
        if (mOriginalMetricsLevel != INetdEventListener::REPORTING_LEVEL_FULL) {
            rv = mNetdSrv->setMetricsReportingLevel(INetdEventListener::REPORTING_LEVEL_FULL);
            ASSERT_TRUE(rv.isOk());
        }
    }

    void TearDown() {
        if (mOriginalMetricsLevel != INetdEventListener::REPORTING_LEVEL_FULL) {
            auto rv = mNetdSrv->setMetricsReportingLevel(mOriginalMetricsLevel);
            ASSERT_TRUE(rv.isOk());
        }

        DnsResponderClient::TearDown();
    }

    bool GetResolverInfo(std::vector<std::string>* servers, std::vector<std::string>* domains,
            __res_params* params, std::vector<ResolverStats>* stats) {
        using android::net::INetd;
        std::vector<int32_t> params32;
        std::vector<int32_t> stats32;
        auto rv = mNetdSrv->getResolverInfo(TEST_NETID, servers, domains, &params32, &stats32);
        if (!rv.isOk() || params32.size() != INetd::RESOLVER_PARAMS_COUNT) {
            return false;
        }
        *params = __res_params {
            .sample_validity = static_cast<uint16_t>(
                    params32[INetd::RESOLVER_PARAMS_SAMPLE_VALIDITY]),
            .success_threshold = static_cast<uint8_t>(
                    params32[INetd::RESOLVER_PARAMS_SUCCESS_THRESHOLD]),
            .min_samples = static_cast<uint8_t>(
                    params32[INetd::RESOLVER_PARAMS_MIN_SAMPLES]),
            .max_samples = static_cast<uint8_t>(
                    params32[INetd::RESOLVER_PARAMS_MAX_SAMPLES]),
            .base_timeout_msec = params32[INetd::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC],
        };
        return ResolverStats::decodeAll(stats32, stats);
    }

    static std::string ToString(const hostent* he) {
        if (he == nullptr) return "<null>";
        char buffer[INET6_ADDRSTRLEN];
        if (!inet_ntop(he->h_addrtype, he->h_addr_list[0], buffer, sizeof(buffer))) {
            return "<invalid>";
        }
        return buffer;
    }

    static std::string ToString(const addrinfo* ai) {
        if (!ai)
            return "<null>";
        for (const auto* aip = ai ; aip != nullptr ; aip = aip->ai_next) {
            char host[NI_MAXHOST];
            int rv = getnameinfo(aip->ai_addr, aip->ai_addrlen, host, sizeof(host), nullptr, 0,
                    NI_NUMERICHOST);
            if (rv != 0)
                return gai_strerror(rv);
            return host;
        }
        return "<invalid>";
    }

    static std::string ToString(const ScopedAddrinfo& ai) { return ToString(ai.get()); }

    size_t GetNumQueries(const test::DNSResponder& dns, const char* name) const {
        auto queries = dns.queries();
        size_t found = 0;
        for (const auto& p : queries) {
            if (p.first == name) {
                ++found;
            }
        }
        return found;
    }

    size_t GetNumQueriesForType(const test::DNSResponder& dns, ns_type type,
                                const char* name) const {
        auto queries = dns.queries();
        size_t found = 0;
        for (const auto& p : queries) {
            if (p.second == type && p.first == name) {
                ++found;
            }
        }
        return found;
    }

    void RunGetAddrInfoStressTest_Binder(unsigned num_hosts, unsigned num_threads,
            unsigned num_queries) {
        std::vector<std::string> domains = { "example.com" };
        std::vector<std::unique_ptr<test::DNSResponder>> dns;
        std::vector<std::string> servers;
        std::vector<DnsResponderClient::Mapping> mappings;
        ASSERT_NO_FATAL_FAILURE(SetupMappings(num_hosts, domains, &mappings));
        ASSERT_NO_FATAL_FAILURE(SetupDNSServers(MAXNS, mappings, &dns, &servers));

        ASSERT_TRUE(SetResolversForNetwork(servers, domains, mDefaultParams_Binder));

        auto t0 = std::chrono::steady_clock::now();
        std::vector<std::thread> threads(num_threads);
        for (std::thread& thread : threads) {
            thread = std::thread([&mappings, num_queries]() {
                for (unsigned i = 0 ; i < num_queries ; ++i) {
                    uint32_t ofs = arc4random_uniform(mappings.size());
                    auto& mapping = mappings[ofs];
                    addrinfo* result = nullptr;
                    int rv = getaddrinfo(mapping.host.c_str(), nullptr, nullptr, &result);
                    EXPECT_EQ(0, rv) << "error [" << rv << "] " << gai_strerror(rv);
                    if (rv == 0) {
                        std::string result_str = ToString(result);
                        EXPECT_TRUE(result_str == mapping.ip4 || result_str == mapping.ip6)
                            << "result='" << result_str << "', ip4='" << mapping.ip4
                            << "', ip6='" << mapping.ip6;
                    }
                    if (result) {
                        freeaddrinfo(result);
                        result = nullptr;
                    }
                }
            });
        }

        for (std::thread& thread : threads) {
            thread.join();
        }
        auto t1 = std::chrono::steady_clock::now();
        ALOGI("%u hosts, %u threads, %u queries, %Es", num_hosts, num_threads, num_queries,
                std::chrono::duration<double>(t1 - t0).count());
        ASSERT_NO_FATAL_FAILURE(ShutdownDNSServers(&dns));
    }

    const std::vector<std::string> mDefaultSearchDomains = { "example.com" };
    // <sample validity in s> <success threshold in percent> <min samples> <max samples>
    const std::vector<int> mDefaultParams_Binder = {
            300,     // SAMPLE_VALIDITY
            25,      // SUCCESS_THRESHOLD
            8,   8,  // {MIN,MAX}_SAMPLES
            100,     // BASE_TIMEOUT_MSEC
    };

  private:
    int mOriginalMetricsLevel;
};

TEST_F(ResolverTest, GetHostByName) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_srv = "53";
    const char* host_name = "hello.example.com.";
    const char *nonexistent_host_name = "nonexistent.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.3");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));

    const hostent* result;

    dns.clearQueries();
    result = gethostbyname("nonexistent");
    EXPECT_EQ(1U, GetNumQueriesForType(dns, ns_type::ns_t_a, nonexistent_host_name));
    ASSERT_TRUE(result == nullptr);
    ASSERT_EQ(HOST_NOT_FOUND, h_errno);

    dns.clearQueries();
    result = gethostbyname("hello");
    EXPECT_EQ(1U, GetNumQueriesForType(dns, ns_type::ns_t_a, host_name));
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ("1.2.3.3", ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);

    dns.stopServer();
}

TEST_F(ResolverTest, GetHostByName_localhost) {
    constexpr char name[] = "localhost";
    constexpr char name_camelcase[] = "LocalHost";
    constexpr char addr[] = "127.0.0.1";
    constexpr char name_ip6[] = "ip6-localhost";
    constexpr char addr_ip6[] = "::1";
    constexpr char name_ip6_dot[] = "ip6-localhost.";
    constexpr char name_ip6_fqdn[] = "ip6-localhost.example.com.";

    // Add a dummy nameserver which shouldn't receive any queries
    constexpr char listen_addr[] = "127.0.0.3";
    constexpr char listen_srv[] = "53";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = {listen_addr};
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));
    dns.clearQueries();

    // Expect no DNS queries; localhost is resolved via /etc/hosts
    const hostent* result = gethostbyname(name);
    EXPECT_TRUE(dns.queries().empty()) << dns.dumpQueries();
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ(addr, ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);

    // Ensure the hosts file resolver ignores case of hostnames
    result = gethostbyname(name_camelcase);
    EXPECT_TRUE(dns.queries().empty()) << dns.dumpQueries();
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ(addr, ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);

    // The hosts file also contains ip6-localhost, but gethostbyname() won't
    // return it unless the RES_USE_INET6 option is set. This would be easy to
    // change, but there's no point in changing the legacy behavior; new code
    // should be calling getaddrinfo() anyway.
    // So we check the legacy behavior, which results in amusing A-record
    // lookups for ip6-localhost, with and without search domains appended.
    dns.clearQueries();
    result = gethostbyname(name_ip6);
    EXPECT_EQ(2, dns.queries().size()) << dns.dumpQueries();
    EXPECT_EQ(1, GetNumQueriesForType(dns, ns_type::ns_t_a, name_ip6_dot)) << dns.dumpQueries();
    EXPECT_EQ(1, GetNumQueriesForType(dns, ns_type::ns_t_a, name_ip6_fqdn)) << dns.dumpQueries();
    ASSERT_TRUE(result == nullptr);

    // Finally, use gethostbyname2() to resolve ip6-localhost to ::1 from
    // the hosts file.
    dns.clearQueries();
    result = gethostbyname2(name_ip6, AF_INET6);
    EXPECT_TRUE(dns.queries().empty()) << dns.dumpQueries();
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(16, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ(addr_ip6, ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);

    dns.stopServer();
}

TEST_F(ResolverTest, GetHostByName_numeric) {
    // Add a dummy nameserver which shouldn't receive any queries
    constexpr char listen_addr[] = "127.0.0.3";
    constexpr char listen_srv[] = "53";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    ASSERT_TRUE(dns.startServer());
    ASSERT_TRUE(
            SetResolversForNetwork({listen_addr}, mDefaultSearchDomains, mDefaultParams_Binder));

    // Numeric v4 address: expect no DNS queries
    constexpr char numeric_v4[] = "192.168.0.1";
    dns.clearQueries();
    const hostent* result = gethostbyname(numeric_v4);
    EXPECT_EQ(0, dns.queries().size());
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);  // v4
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ(numeric_v4, ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);

    // gethostbyname() recognizes a v6 address, and fails with no DNS queries
    constexpr char numeric_v6[] = "2001:db8::42";
    dns.clearQueries();
    result = gethostbyname(numeric_v6);
    EXPECT_EQ(0, dns.queries().size());
    EXPECT_TRUE(result == nullptr);

    // Numeric v6 address with gethostbyname2(): succeeds with no DNS queries
    dns.clearQueries();
    result = gethostbyname2(numeric_v6, AF_INET6);
    EXPECT_EQ(0, dns.queries().size());
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(16, result->h_length);  // v6
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ(numeric_v6, ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);

    // Numeric v6 address with scope work with getaddrinfo(),
    // but gethostbyname2() does not understand them; it issues two dns
    // queries, then fails. This hardly ever happens, there's no point
    // in fixing this. This test simply verifies the current (bogus)
    // behavior to avoid further regressions (like crashes, or leaks).
    constexpr char numeric_v6_scope[] = "fe80::1%lo";
    dns.clearQueries();
    result = gethostbyname2(numeric_v6_scope, AF_INET6);
    EXPECT_EQ(2, dns.queries().size());  // OUCH!
    ASSERT_TRUE(result == nullptr);

    dns.stopServer();
}

TEST_F(ResolverTest, BinderSerialization) {
    using android::net::INetd;
    std::vector<int> params_offsets = {
        INetd::RESOLVER_PARAMS_SAMPLE_VALIDITY,
        INetd::RESOLVER_PARAMS_SUCCESS_THRESHOLD,
        INetd::RESOLVER_PARAMS_MIN_SAMPLES,
        INetd::RESOLVER_PARAMS_MAX_SAMPLES,
        INetd::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC,
    };
    int size = static_cast<int>(params_offsets.size());
    EXPECT_EQ(size, INetd::RESOLVER_PARAMS_COUNT);
    std::sort(params_offsets.begin(), params_offsets.end());
    for (int i = 0 ; i < size ; ++i) {
        EXPECT_EQ(params_offsets[i], i);
    }
}

TEST_F(ResolverTest, GetHostByName_Binder) {
    using android::net::INetd;

    std::vector<std::string> domains = { "example.com" };
    std::vector<std::unique_ptr<test::DNSResponder>> dns;
    std::vector<std::string> servers;
    std::vector<Mapping> mappings;
    ASSERT_NO_FATAL_FAILURE(SetupMappings(1, domains, &mappings));
    ASSERT_NO_FATAL_FAILURE(SetupDNSServers(4, mappings, &dns, &servers));
    ASSERT_EQ(1U, mappings.size());
    const Mapping& mapping = mappings[0];

    ASSERT_TRUE(SetResolversForNetwork(servers, domains, mDefaultParams_Binder));

    const hostent* result = gethostbyname(mapping.host.c_str());
    size_t total_queries = std::accumulate(dns.begin(), dns.end(), 0,
            [this, &mapping](size_t total, auto& d) {
                return total + GetNumQueriesForType(*d, ns_type::ns_t_a, mapping.entry.c_str());
            });

    EXPECT_LE(1U, total_queries);
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ(mapping.ip4, ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);

    std::vector<std::string> res_servers;
    std::vector<std::string> res_domains;
    __res_params res_params;
    std::vector<ResolverStats> res_stats;
    ASSERT_TRUE(GetResolverInfo(&res_servers, &res_domains, &res_params, &res_stats));
    EXPECT_EQ(servers.size(), res_servers.size());
    EXPECT_EQ(domains.size(), res_domains.size());
    ASSERT_EQ(INetd::RESOLVER_PARAMS_COUNT, mDefaultParams_Binder.size());
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_SAMPLE_VALIDITY],
            res_params.sample_validity);
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_SUCCESS_THRESHOLD],
            res_params.success_threshold);
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_MIN_SAMPLES], res_params.min_samples);
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_MAX_SAMPLES], res_params.max_samples);
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC],
              res_params.base_timeout_msec);
    EXPECT_EQ(servers.size(), res_stats.size());

    EXPECT_TRUE(UnorderedCompareArray(res_servers, servers));
    EXPECT_TRUE(UnorderedCompareArray(res_domains, domains));

    ASSERT_NO_FATAL_FAILURE(ShutdownDNSServers(&dns));
}

TEST_F(ResolverTest, GetAddrInfo) {
    const char* listen_addr = "127.0.0.4";
    const char* listen_addr2 = "127.0.0.5";
    const char* listen_srv = "53";
    const char* host_name = "howdy.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.4");
    dns.addMapping(host_name, ns_type::ns_t_aaaa, "::1.2.3.4");
    ASSERT_TRUE(dns.startServer());

    test::DNSResponder dns2(listen_addr2, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns2.addMapping(host_name, ns_type::ns_t_a, "1.2.3.4");
    dns2.addMapping(host_name, ns_type::ns_t_aaaa, "::1.2.3.4");
    ASSERT_TRUE(dns2.startServer());

    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));
    dns.clearQueries();
    dns2.clearQueries();

    ScopedAddrinfo result = safe_getaddrinfo("howdy", nullptr, nullptr);
    EXPECT_TRUE(result != nullptr);
    size_t found = GetNumQueries(dns, host_name);
    EXPECT_LE(1U, found);
    // Could be A or AAAA
    std::string result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.4" || result_str == "::1.2.3.4")
        << ", result_str='" << result_str << "'";

    // Verify that the name is cached.
    size_t old_found = found;
    result = safe_getaddrinfo("howdy", nullptr, nullptr);
    EXPECT_TRUE(result != nullptr);
    found = GetNumQueries(dns, host_name);
    EXPECT_LE(1U, found);
    EXPECT_EQ(old_found, found);
    result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.4" || result_str == "::1.2.3.4")
        << result_str;

    // Change the DNS resolver, ensure that queries are still cached.
    servers = { listen_addr2 };
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));
    dns.clearQueries();
    dns2.clearQueries();

    result = safe_getaddrinfo("howdy", nullptr, nullptr);
    EXPECT_TRUE(result != nullptr);
    found = GetNumQueries(dns, host_name);
    size_t found2 = GetNumQueries(dns2, host_name);
    EXPECT_EQ(0U, found);
    EXPECT_LE(0U, found2);

    // Could be A or AAAA
    result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.4" || result_str == "::1.2.3.4")
        << ", result_str='" << result_str << "'";

    dns.stopServer();
    dns2.stopServer();
}

TEST_F(ResolverTest, GetAddrInfoV4) {
    constexpr char listen_addr[] = "127.0.0.5";
    constexpr char listen_srv[] = "53";
    constexpr char host_name[] = "hola.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.5");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));

    addrinfo hints = {.ai_family = AF_INET};
    ScopedAddrinfo result = safe_getaddrinfo("hola", nullptr, &hints);
    EXPECT_TRUE(result != nullptr);
    EXPECT_EQ(1U, GetNumQueries(dns, host_name));
    EXPECT_EQ("1.2.3.5", ToString(result));
}

TEST_F(ResolverTest, GetAddrInfo_localhost) {
    constexpr char name[] = "localhost";
    constexpr char addr[] = "127.0.0.1";
    constexpr char name_ip6[] = "ip6-localhost";
    constexpr char addr_ip6[] = "::1";

    // Add a dummy nameserver which shouldn't receive any queries
    constexpr char listen_addr[] = "127.0.0.5";
    constexpr char listen_srv[] = "53";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = {listen_addr};
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));

    ScopedAddrinfo result = safe_getaddrinfo(name, nullptr, nullptr);
    EXPECT_TRUE(result != nullptr);
    // Expect no DNS queries; localhost is resolved via /etc/hosts
    EXPECT_TRUE(dns.queries().empty()) << dns.dumpQueries();
    EXPECT_EQ(addr, ToString(result));

    result = safe_getaddrinfo(name_ip6, nullptr, nullptr);
    EXPECT_TRUE(result != nullptr);
    // Expect no DNS queries; ip6-localhost is resolved via /etc/hosts
    EXPECT_TRUE(dns.queries().empty()) << dns.dumpQueries();
    EXPECT_EQ(addr_ip6, ToString(result));
}

TEST_F(ResolverTest, GetHostByNameBrokenEdns) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_srv = "53";
    const char* host_name = "edns.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.3");
    dns.setFailOnEdns(true);  // This is the only change from the basic test.
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));

    const hostent* result;

    dns.clearQueries();
    result = gethostbyname("edns");
    EXPECT_EQ(1U, GetNumQueriesForType(dns, ns_type::ns_t_a, host_name));
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ("1.2.3.3", ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);
}

TEST_F(ResolverTest, GetAddrInfoBrokenEdns) {
    const char* listen_addr = "127.0.0.5";
    const char* listen_srv = "53";
    const char* host_name = "edns2.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.5");
    dns.setFailOnEdns(true);  // This is the only change from the basic test.
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));

    addrinfo hints = {.ai_family = AF_INET};
    ScopedAddrinfo result = safe_getaddrinfo("edns2", nullptr, &hints);
    EXPECT_TRUE(result != nullptr);
    EXPECT_EQ(1U, GetNumQueries(dns, host_name));
    EXPECT_EQ("1.2.3.5", ToString(result));
}

TEST_F(ResolverTest, MultidomainResolution) {
    std::vector<std::string> searchDomains = { "example1.com", "example2.com", "example3.com" };
    const char* listen_addr = "127.0.0.6";
    const char* listen_srv = "53";
    const char* host_name = "nihao.example2.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.3");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    ASSERT_TRUE(SetResolversForNetwork(servers, searchDomains, mDefaultParams_Binder));

    dns.clearQueries();
    const hostent* result = gethostbyname("nihao");
    EXPECT_EQ(1U, GetNumQueriesForType(dns, ns_type::ns_t_a, host_name));
    ASSERT_FALSE(result == nullptr);
    ASSERT_EQ(4, result->h_length);
    ASSERT_FALSE(result->h_addr_list[0] == nullptr);
    EXPECT_EQ("1.2.3.3", ToString(result));
    EXPECT_TRUE(result->h_addr_list[1] == nullptr);
    dns.stopServer();
}

TEST_F(ResolverTest, GetAddrInfoV6_numeric) {
    constexpr char listen_addr0[] = "127.0.0.7";
    constexpr char listen_srv[] = "53";
    constexpr char host_name[] = "ohayou.example.com.";
    constexpr char numeric_addr[] = "fe80::1%lo";

    test::DNSResponder dns(listen_addr0, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.setResponseProbability(0.0);
    dns.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::5");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = {listen_addr0};
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));

    addrinfo hints = {.ai_family = AF_INET6};
    ScopedAddrinfo result = safe_getaddrinfo(numeric_addr, nullptr, &hints);
    EXPECT_TRUE(result != nullptr);
    EXPECT_EQ(numeric_addr, ToString(result));
    EXPECT_TRUE(dns.queries().empty());  // Ensure no DNS queries were sent out

    // Now try a non-numeric hostname query with the AI_NUMERICHOST flag set.
    // We should fail without sending out a DNS query.
    hints.ai_flags |= AI_NUMERICHOST;
    result = safe_getaddrinfo(host_name, nullptr, &hints);
    EXPECT_TRUE(result == nullptr);
    EXPECT_TRUE(dns.queries().empty());  // Ensure no DNS queries were sent out
}

TEST_F(ResolverTest, GetAddrInfoV6_failing) {
    const char* listen_addr0 = "127.0.0.7";
    const char* listen_addr1 = "127.0.0.8";
    const char* listen_srv = "53";
    const char* host_name = "ohayou.example.com.";
    test::DNSResponder dns0(listen_addr0, listen_srv, 250, ns_rcode::ns_r_servfail);
    test::DNSResponder dns1(listen_addr1, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns0.setResponseProbability(0.0);
    dns0.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::5");
    dns1.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::6");
    ASSERT_TRUE(dns0.startServer());
    ASSERT_TRUE(dns1.startServer());
    std::vector<std::string> servers = { listen_addr0, listen_addr1 };
    // <sample validity in s> <success threshold in percent> <min samples> <max samples>
    int sample_count = 8;
    const std::vector<int> params = { 300, 25, sample_count, sample_count };
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, params));

    // Repeatedly perform resolutions for non-existing domains until MAXNSSAMPLES resolutions have
    // reached the dns0, which is set to fail. No more requests should then arrive at that server
    // for the next sample_lifetime seconds.
    // TODO: This approach is implementation-dependent, change once metrics reporting is available.
    addrinfo hints = {.ai_family = AF_INET6};
    for (int i = 0 ; i < sample_count ; ++i) {
        std::string domain = StringPrintf("nonexistent%d", i);
        ScopedAddrinfo result = safe_getaddrinfo(domain.c_str(), nullptr, &hints);
    }
    // Due to 100% errors for all possible samples, the server should be ignored from now on and
    // only the second one used for all following queries, until NSSAMPLE_VALIDITY is reached.
    dns0.clearQueries();
    dns1.clearQueries();
    ScopedAddrinfo result = safe_getaddrinfo("ohayou", nullptr, &hints);
    EXPECT_TRUE(result != nullptr);
    EXPECT_EQ(0U, GetNumQueries(dns0, host_name));
    EXPECT_EQ(1U, GetNumQueries(dns1, host_name));
}

TEST_F(ResolverTest, GetAddrInfoV6_nonresponsive) {
    const char* listen_addr0 = "127.0.0.7";
    const char* listen_addr1 = "127.0.0.8";
    const char* listen_srv = "53";
    const char* host_name1 = "ohayou.example.com.";
    const char* host_name2 = "ciao.example.com.";

    // dns0 does not respond with 100% probability, while
    // dns1 responds normally, at least initially.
    test::DNSResponder dns0(listen_addr0, listen_srv, 250, static_cast<ns_rcode>(-1));
    test::DNSResponder dns1(listen_addr1, listen_srv, 250, static_cast<ns_rcode>(-1));
    dns0.setResponseProbability(0.0);
    dns0.addMapping(host_name1, ns_type::ns_t_aaaa, "2001:db8::5");
    dns1.addMapping(host_name1, ns_type::ns_t_aaaa, "2001:db8::6");
    dns0.addMapping(host_name2, ns_type::ns_t_aaaa, "2001:db8::5");
    dns1.addMapping(host_name2, ns_type::ns_t_aaaa, "2001:db8::6");
    ASSERT_TRUE(dns0.startServer());
    ASSERT_TRUE(dns1.startServer());
    std::vector<std::string> servers = {listen_addr0, listen_addr1};
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));

    const addrinfo hints = {.ai_family = AF_INET6};

    // dns0 will ignore the request, and we'll fallback to dns1 after the first
    // retry.
    ScopedAddrinfo result = safe_getaddrinfo(host_name1, nullptr, &hints);
    EXPECT_TRUE(result != nullptr);
    EXPECT_EQ(1U, GetNumQueries(dns0, host_name1));
    EXPECT_EQ(1U, GetNumQueries(dns1, host_name1));

    // Now make dns1 also ignore 100% requests... The resolve should alternate
    // retries between the nameservers and fail after 4 attempts.
    dns1.setResponseProbability(0.0);
    addrinfo* result2 = nullptr;
    EXPECT_EQ(EAI_NODATA, getaddrinfo(host_name2, nullptr, &hints, &result2));
    EXPECT_EQ(nullptr, result2);
    EXPECT_EQ(4U, GetNumQueries(dns0, host_name2));
    EXPECT_EQ(4U, GetNumQueries(dns1, host_name2));
}

TEST_F(ResolverTest, GetAddrInfoV6_concurrent) {
    const char* listen_addr0 = "127.0.0.9";
    const char* listen_addr1 = "127.0.0.10";
    const char* listen_addr2 = "127.0.0.11";
    const char* listen_srv = "53";
    const char* host_name = "konbanha.example.com.";
    test::DNSResponder dns0(listen_addr0, listen_srv, 250, ns_rcode::ns_r_servfail);
    test::DNSResponder dns1(listen_addr1, listen_srv, 250, ns_rcode::ns_r_servfail);
    test::DNSResponder dns2(listen_addr2, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns0.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::5");
    dns1.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::6");
    dns2.addMapping(host_name, ns_type::ns_t_aaaa, "2001:db8::7");
    ASSERT_TRUE(dns0.startServer());
    ASSERT_TRUE(dns1.startServer());
    ASSERT_TRUE(dns2.startServer());
    const std::vector<std::string> servers = { listen_addr0, listen_addr1, listen_addr2 };
    std::vector<std::thread> threads(10);
    for (std::thread& thread : threads) {
       thread = std::thread([this, &servers]() {
            unsigned delay = arc4random_uniform(1*1000*1000); // <= 1s
            usleep(delay);
            std::vector<std::string> serverSubset;
            for (const auto& server : servers) {
                if (arc4random_uniform(2)) {
                    serverSubset.push_back(server);
                }
            }
            if (serverSubset.empty()) serverSubset = servers;
            ASSERT_TRUE(SetResolversForNetwork(serverSubset, mDefaultSearchDomains,
                    mDefaultParams_Binder));
            addrinfo hints = {.ai_family = AF_INET6};
            addrinfo* result = nullptr;
            int rv = getaddrinfo("konbanha", nullptr, &hints, &result);
            EXPECT_EQ(0, rv) << "error [" << rv << "] " << gai_strerror(rv);
            if (result) {
                freeaddrinfo(result);
                result = nullptr;
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
}

TEST_F(ResolverTest, GetAddrInfoStressTest_Binder_100) {
    const unsigned num_hosts = 100;
    const unsigned num_threads = 100;
    const unsigned num_queries = 100;
    ASSERT_NO_FATAL_FAILURE(RunGetAddrInfoStressTest_Binder(num_hosts, num_threads, num_queries));
}

TEST_F(ResolverTest, GetAddrInfoStressTest_Binder_100000) {
    const unsigned num_hosts = 100000;
    const unsigned num_threads = 100;
    const unsigned num_queries = 100;
    ASSERT_NO_FATAL_FAILURE(RunGetAddrInfoStressTest_Binder(num_hosts, num_threads, num_queries));
}

TEST_F(ResolverTest, EmptySetup) {
    using android::net::INetd;
    std::vector<std::string> servers;
    std::vector<std::string> domains;
    ASSERT_TRUE(SetResolversForNetwork(servers, domains, mDefaultParams_Binder));
    std::vector<std::string> res_servers;
    std::vector<std::string> res_domains;
    __res_params res_params;
    std::vector<ResolverStats> res_stats;
    ASSERT_TRUE(GetResolverInfo(&res_servers, &res_domains, &res_params, &res_stats));
    EXPECT_EQ(0U, res_servers.size());
    EXPECT_EQ(0U, res_domains.size());
    ASSERT_EQ(INetd::RESOLVER_PARAMS_COUNT, mDefaultParams_Binder.size());
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_SAMPLE_VALIDITY],
            res_params.sample_validity);
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_SUCCESS_THRESHOLD],
            res_params.success_threshold);
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_MIN_SAMPLES], res_params.min_samples);
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_MAX_SAMPLES], res_params.max_samples);
    EXPECT_EQ(mDefaultParams_Binder[INetd::RESOLVER_PARAMS_BASE_TIMEOUT_MSEC],
              res_params.base_timeout_msec);
}

TEST_F(ResolverTest, SearchPathChange) {
    const char* listen_addr = "127.0.0.13";
    const char* listen_srv = "53";
    const char* host_name1 = "test13.domain1.org.";
    const char* host_name2 = "test13.domain2.org.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name1, ns_type::ns_t_aaaa, "2001:db8::13");
    dns.addMapping(host_name2, ns_type::ns_t_aaaa, "2001:db8::1:13");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };
    std::vector<std::string> domains = { "domain1.org" };
    ASSERT_TRUE(SetResolversForNetwork(servers, domains, mDefaultParams_Binder));

    const addrinfo hints = {.ai_family = AF_INET6};
    ScopedAddrinfo result = safe_getaddrinfo("test13", nullptr, &hints);
    EXPECT_TRUE(result != nullptr);
    EXPECT_EQ(1U, dns.queries().size());
    EXPECT_EQ(1U, GetNumQueries(dns, host_name1));
    EXPECT_EQ("2001:db8::13", ToString(result));

    // Test that changing the domain search path on its own works.
    domains = { "domain2.org" };
    ASSERT_TRUE(SetResolversForNetwork(servers, domains, mDefaultParams_Binder));
    dns.clearQueries();

    result = safe_getaddrinfo("test13", nullptr, &hints);
    EXPECT_TRUE(result != nullptr);
    EXPECT_EQ(1U, dns.queries().size());
    EXPECT_EQ(1U, GetNumQueries(dns, host_name2));
    EXPECT_EQ("2001:db8::1:13", ToString(result));
}

TEST_F(ResolverTest, MaxServerPrune_Binder) {
    using android::net::INetd;

    std::vector<std::string> domains = { "example.com" };
    std::vector<std::unique_ptr<test::DNSResponder>> dns;
    std::vector<std::string> servers;
    std::vector<Mapping> mappings;
    ASSERT_NO_FATAL_FAILURE(SetupMappings(1, domains, &mappings));
    ASSERT_NO_FATAL_FAILURE(SetupDNSServers(MAXNS + 1, mappings, &dns, &servers));

    ASSERT_TRUE(SetResolversForNetwork(servers, domains,  mDefaultParams_Binder));

    std::vector<std::string> res_servers;
    std::vector<std::string> res_domains;
    __res_params res_params;
    std::vector<ResolverStats> res_stats;
    ASSERT_TRUE(GetResolverInfo(&res_servers, &res_domains, &res_params, &res_stats));
    EXPECT_EQ(static_cast<size_t>(MAXNS), res_servers.size());

    ASSERT_NO_FATAL_FAILURE(ShutdownDNSServers(&dns));
}

static std::string base64Encode(const std::vector<uint8_t>& input) {
    size_t out_len;
    EXPECT_EQ(1, EVP_EncodedLength(&out_len, input.size()));
    // out_len includes the trailing NULL.
    uint8_t output_bytes[out_len];
    EXPECT_EQ(out_len - 1, EVP_EncodeBlock(output_bytes, input.data(), input.size()));
    return std::string(reinterpret_cast<char*>(output_bytes));
}

// Test what happens if the specified TLS server is nonexistent.
TEST_F(ResolverTest, GetHostByName_TlsMissing) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_srv = "53";
    const char* host_name = "tlsmissing.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.3");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };

    // There's nothing listening on this address, so validation will either fail or
    /// hang.  Either way, queries will continue to flow to the DNSResponder.
    ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder, "", {}));

    const hostent* result;

    result = gethostbyname("tlsmissing");
    ASSERT_FALSE(result == nullptr);
    EXPECT_EQ("1.2.3.3", ToString(result));

    // Clear TLS bit.
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains,  mDefaultParams_Binder));
    dns.stopServer();
}

// Test what happens if the specified TLS server replies with garbage.
TEST_F(ResolverTest, GetHostByName_TlsBroken) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_srv = "53";
    const char* host_name1 = "tlsbroken1.example.com.";
    const char* host_name2 = "tlsbroken2.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name1, ns_type::ns_t_a, "1.2.3.1");
    dns.addMapping(host_name2, ns_type::ns_t_a, "1.2.3.2");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };

    // Bind the specified private DNS socket but don't respond to any client sockets yet.
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    ASSERT_TRUE(s >= 0);
    struct sockaddr_in tlsServer = {
        .sin_family = AF_INET,
        .sin_port = htons(853),
    };
    ASSERT_TRUE(inet_pton(AF_INET, listen_addr, &tlsServer.sin_addr));
    enableSockopt(s, SOL_SOCKET, SO_REUSEPORT);
    enableSockopt(s, SOL_SOCKET, SO_REUSEADDR);
    ASSERT_FALSE(bind(s, reinterpret_cast<struct sockaddr*>(&tlsServer), sizeof(tlsServer)));
    ASSERT_FALSE(listen(s, 1));

    // Trigger TLS validation.
    ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder, "", {}));

    struct sockaddr_storage cliaddr;
    socklen_t sin_size = sizeof(cliaddr);
    int new_fd = accept4(s, reinterpret_cast<struct sockaddr *>(&cliaddr), &sin_size, SOCK_CLOEXEC);
    ASSERT_TRUE(new_fd > 0);

    // We've received the new file descriptor but not written to it or closed, so the
    // validation is still pending.  Queries should still flow correctly because the
    // server is not used until validation succeeds.
    const hostent* result;
    result = gethostbyname("tlsbroken1");
    ASSERT_FALSE(result == nullptr);
    EXPECT_EQ("1.2.3.1", ToString(result));

    // Now we cause the validation to fail.
    std::string garbage = "definitely not a valid TLS ServerHello";
    write(new_fd, garbage.data(), garbage.size());
    close(new_fd);

    // Validation failure shouldn't interfere with lookups, because lookups won't be sent
    // to the TLS server unless validation succeeds.
    result = gethostbyname("tlsbroken2");
    ASSERT_FALSE(result == nullptr);
    EXPECT_EQ("1.2.3.2", ToString(result));

    // Clear TLS bit.
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains,  mDefaultParams_Binder));
    dns.stopServer();
    close(s);
}

TEST_F(ResolverTest, GetHostByName_Tls) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_udp = "53";
    const char* listen_tls = "853";
    const char* host_name1 = "tls1.example.com.";
    const char* host_name2 = "tls2.example.com.";
    const char* host_name3 = "tls3.example.com.";
    test::DNSResponder dns(listen_addr, listen_udp, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name1, ns_type::ns_t_a, "1.2.3.1");
    dns.addMapping(host_name2, ns_type::ns_t_a, "1.2.3.2");
    dns.addMapping(host_name3, ns_type::ns_t_a, "1.2.3.3");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };

    test::DnsTlsFrontend tls(listen_addr, listen_tls, listen_addr, listen_udp);
    ASSERT_TRUE(tls.startServer());
    ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder, "", {}));

    const hostent* result;

    // Wait for validation to complete.
    EXPECT_TRUE(tls.waitForQueries(1, 5000));

    result = gethostbyname("tls1");
    ASSERT_FALSE(result == nullptr);
    EXPECT_EQ("1.2.3.1", ToString(result));

    // Wait for query to get counted.
    EXPECT_TRUE(tls.waitForQueries(2, 5000));

    // Stop the TLS server.  Since we're in opportunistic mode, queries will
    // fall back to the locally-assigned (clear text) nameservers.
    tls.stopServer();

    dns.clearQueries();
    result = gethostbyname("tls2");
    EXPECT_FALSE(result == nullptr);
    EXPECT_EQ("1.2.3.2", ToString(result));
    const auto queries = dns.queries();
    EXPECT_EQ(1U, queries.size());
    EXPECT_EQ("tls2.example.com.", queries[0].first);
    EXPECT_EQ(ns_t_a, queries[0].second);

    // Reset the resolvers without enabling TLS.  Queries should still be routed
    // to the UDP endpoint.
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains, mDefaultParams_Binder));

    result = gethostbyname("tls3");
    ASSERT_FALSE(result == nullptr);
    EXPECT_EQ("1.2.3.3", ToString(result));

    dns.stopServer();
}

TEST_F(ResolverTest, GetHostByName_TlsFingerprint) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_udp = "53";
    const char* listen_tls = "853";
    test::DNSResponder dns(listen_addr, listen_udp, 250, ns_rcode::ns_r_servfail);
    ASSERT_TRUE(dns.startServer());
    for (int chain_length = 1; chain_length <= 3; ++chain_length) {
        std::string host_name = StringPrintf("tlsfingerprint%d.example.com.", chain_length);
        dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.1");
        std::vector<std::string> servers = { listen_addr };

        test::DnsTlsFrontend tls(listen_addr, listen_tls, listen_addr, listen_udp);
        tls.set_chain_length(chain_length);
        ASSERT_TRUE(tls.startServer());
        ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder, "",
                { base64Encode(tls.fingerprint()) }));

        const hostent* result;

        // Wait for validation to complete.
        EXPECT_TRUE(tls.waitForQueries(1, 5000));

        result = gethostbyname(StringPrintf("tlsfingerprint%d", chain_length).c_str());
        EXPECT_FALSE(result == nullptr);
        if (result) {
            EXPECT_EQ("1.2.3.1", ToString(result));

            // Wait for query to get counted.
            EXPECT_TRUE(tls.waitForQueries(2, 5000));
        }

        // Clear TLS bit to ensure revalidation.
        ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains,  mDefaultParams_Binder));
        tls.stopServer();
    }
    dns.stopServer();
}

TEST_F(ResolverTest, GetHostByName_BadTlsFingerprint) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_udp = "53";
    const char* listen_tls = "853";
    const char* host_name = "badtlsfingerprint.example.com.";
    test::DNSResponder dns(listen_addr, listen_udp, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.1");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };

    test::DnsTlsFrontend tls(listen_addr, listen_tls, listen_addr, listen_udp);
    ASSERT_TRUE(tls.startServer());
    std::vector<uint8_t> bad_fingerprint = tls.fingerprint();
    bad_fingerprint[5] += 1;  // Corrupt the fingerprint.
    ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder, "",
            { base64Encode(bad_fingerprint) }));

    // The initial validation should fail at the fingerprint check before
    // issuing a query.
    EXPECT_FALSE(tls.waitForQueries(1, 500));

    // A fingerprint was provided and failed to match, so the query should fail.
    EXPECT_EQ(nullptr, gethostbyname("badtlsfingerprint"));

    // Clear TLS bit.
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains,  mDefaultParams_Binder));
    tls.stopServer();
    dns.stopServer();
}

// Test that we can pass two different fingerprints, and connection succeeds as long as
// at least one of them matches the server.
TEST_F(ResolverTest, GetHostByName_TwoTlsFingerprints) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_udp = "53";
    const char* listen_tls = "853";
    const char* host_name = "twotlsfingerprints.example.com.";
    test::DNSResponder dns(listen_addr, listen_udp, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.1");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };

    test::DnsTlsFrontend tls(listen_addr, listen_tls, listen_addr, listen_udp);
    ASSERT_TRUE(tls.startServer());
    std::vector<uint8_t> bad_fingerprint = tls.fingerprint();
    bad_fingerprint[5] += 1;  // Corrupt the fingerprint.
    ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder, "",
            { base64Encode(bad_fingerprint), base64Encode(tls.fingerprint()) }));

    const hostent* result;

    // Wait for validation to complete.
    EXPECT_TRUE(tls.waitForQueries(1, 5000));

    result = gethostbyname("twotlsfingerprints");
    ASSERT_FALSE(result == nullptr);
    EXPECT_EQ("1.2.3.1", ToString(result));

    // Wait for query to get counted.
    EXPECT_TRUE(tls.waitForQueries(2, 5000));

    // Clear TLS bit.
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains,  mDefaultParams_Binder));
    tls.stopServer();
    dns.stopServer();
}

TEST_F(ResolverTest, GetHostByName_TlsFingerprintGoesBad) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_udp = "53";
    const char* listen_tls = "853";
    const char* host_name1 = "tlsfingerprintgoesbad1.example.com.";
    const char* host_name2 = "tlsfingerprintgoesbad2.example.com.";
    test::DNSResponder dns(listen_addr, listen_udp, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name1, ns_type::ns_t_a, "1.2.3.1");
    dns.addMapping(host_name2, ns_type::ns_t_a, "1.2.3.2");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };

    test::DnsTlsFrontend tls(listen_addr, listen_tls, listen_addr, listen_udp);
    ASSERT_TRUE(tls.startServer());
    ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder, "",
            { base64Encode(tls.fingerprint()) }));

    const hostent* result;

    // Wait for validation to complete.
    EXPECT_TRUE(tls.waitForQueries(1, 5000));

    result = gethostbyname("tlsfingerprintgoesbad1");
    ASSERT_FALSE(result == nullptr);
    EXPECT_EQ("1.2.3.1", ToString(result));

    // Wait for query to get counted.
    EXPECT_TRUE(tls.waitForQueries(2, 5000));

    // Restart the TLS server.  This will generate a new certificate whose fingerprint
    // no longer matches the stored fingerprint.
    tls.stopServer();
    tls.startServer();

    result = gethostbyname("tlsfingerprintgoesbad2");
    ASSERT_TRUE(result == nullptr);
    EXPECT_EQ(HOST_NOT_FOUND, h_errno);

    // Clear TLS bit.
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains,  mDefaultParams_Binder));
    tls.stopServer();
    dns.stopServer();
}

TEST_F(ResolverTest, GetHostByName_TlsFailover) {
    const char* listen_addr1 = "127.0.0.3";
    const char* listen_addr2 = "127.0.0.4";
    const char* listen_udp = "53";
    const char* listen_tls = "853";
    const char* host_name1 = "tlsfailover1.example.com.";
    const char* host_name2 = "tlsfailover2.example.com.";
    test::DNSResponder dns1(listen_addr1, listen_udp, 250, ns_rcode::ns_r_servfail);
    test::DNSResponder dns2(listen_addr2, listen_udp, 250, ns_rcode::ns_r_servfail);
    dns1.addMapping(host_name1, ns_type::ns_t_a, "1.2.3.1");
    dns1.addMapping(host_name2, ns_type::ns_t_a, "1.2.3.2");
    dns2.addMapping(host_name1, ns_type::ns_t_a, "1.2.3.3");
    dns2.addMapping(host_name2, ns_type::ns_t_a, "1.2.3.4");
    ASSERT_TRUE(dns1.startServer());
    ASSERT_TRUE(dns2.startServer());
    std::vector<std::string> servers = { listen_addr1, listen_addr2 };

    test::DnsTlsFrontend tls1(listen_addr1, listen_tls, listen_addr1, listen_udp);
    test::DnsTlsFrontend tls2(listen_addr2, listen_tls, listen_addr2, listen_udp);
    ASSERT_TRUE(tls1.startServer());
    ASSERT_TRUE(tls2.startServer());
    ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder, "",
            { base64Encode(tls1.fingerprint()), base64Encode(tls2.fingerprint()) }));

    const hostent* result;

    // Wait for validation to complete.
    EXPECT_TRUE(tls1.waitForQueries(1, 5000));
    EXPECT_TRUE(tls2.waitForQueries(1, 5000));

    result = gethostbyname("tlsfailover1");
    ASSERT_FALSE(result == nullptr);
    EXPECT_EQ("1.2.3.1", ToString(result));

    // Wait for query to get counted.
    EXPECT_TRUE(tls1.waitForQueries(2, 5000));
    // No new queries should have reached tls2.
    EXPECT_EQ(1, tls2.queries());

    // Stop tls1.  Subsequent queries should attempt to reach tls1, fail, and retry to tls2.
    tls1.stopServer();

    result = gethostbyname("tlsfailover2");
    EXPECT_EQ("1.2.3.4", ToString(result));

    // Wait for query to get counted.
    EXPECT_TRUE(tls2.waitForQueries(2, 5000));

    // No additional queries should have reached the insecure servers.
    EXPECT_EQ(2U, dns1.queries().size());
    EXPECT_EQ(2U, dns2.queries().size());

    // Clear TLS bit.
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains,  mDefaultParams_Binder));
    tls2.stopServer();
    dns1.stopServer();
    dns2.stopServer();
}

TEST_F(ResolverTest, GetHostByName_BadTlsName) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_udp = "53";
    const char* listen_tls = "853";
    const char* host_name = "badtlsname.example.com.";
    test::DNSResponder dns(listen_addr, listen_udp, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.1");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };

    test::DnsTlsFrontend tls(listen_addr, listen_tls, listen_addr, listen_udp);
    ASSERT_TRUE(tls.startServer());
    ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder,
            "www.example.com", {}));

    // The TLS server's certificate doesn't chain to a known CA, and a nonempty name was specified,
    // so the client should fail the TLS handshake before ever issuing a query.
    EXPECT_FALSE(tls.waitForQueries(1, 500));

    // The query should fail hard, because a name was specified.
    EXPECT_EQ(nullptr, gethostbyname("badtlsname"));

    // Clear TLS bit.
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains,  mDefaultParams_Binder));
    tls.stopServer();
    dns.stopServer();
}

TEST_F(ResolverTest, GetAddrInfo_Tls) {
    const char* listen_addr = "127.0.0.3";
    const char* listen_udp = "53";
    const char* listen_tls = "853";
    const char* host_name = "addrinfotls.example.com.";
    test::DNSResponder dns(listen_addr, listen_udp, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.4");
    dns.addMapping(host_name, ns_type::ns_t_aaaa, "::1.2.3.4");
    ASSERT_TRUE(dns.startServer());
    std::vector<std::string> servers = { listen_addr };

    test::DnsTlsFrontend tls(listen_addr, listen_tls, listen_addr, listen_udp);
    ASSERT_TRUE(tls.startServer());
    ASSERT_TRUE(SetResolversWithTls(servers, mDefaultSearchDomains, mDefaultParams_Binder, "",
            { base64Encode(tls.fingerprint()) }));

    // Wait for validation to complete.
    EXPECT_TRUE(tls.waitForQueries(1, 5000));

    dns.clearQueries();
    ScopedAddrinfo result = safe_getaddrinfo("addrinfotls", nullptr, nullptr);
    EXPECT_TRUE(result != nullptr);
    size_t found = GetNumQueries(dns, host_name);
    EXPECT_LE(1U, found);
    // Could be A or AAAA
    std::string result_str = ToString(result);
    EXPECT_TRUE(result_str == "1.2.3.4" || result_str == "::1.2.3.4")
        << ", result_str='" << result_str << "'";
    // Wait for both A and AAAA queries to get counted.
    EXPECT_TRUE(tls.waitForQueries(3, 5000));

    // Clear TLS bit.
    ASSERT_TRUE(SetResolversForNetwork(servers, mDefaultSearchDomains,  mDefaultParams_Binder));
    tls.stopServer();
    dns.stopServer();
}

TEST_F(ResolverTest, TlsBypass) {
    const char OFF[] = "off";
    const char OPPORTUNISTIC[] = "opportunistic";
    const char STRICT[] = "strict";

    const char GETHOSTBYNAME[] = "gethostbyname";
    const char GETADDRINFO[] = "getaddrinfo";
    const char GETADDRINFOFORNET[] = "getaddrinfofornet";

    const unsigned BYPASS_NETID = NETID_USE_LOCAL_NAMESERVERS | TEST_NETID;

    const std::vector<uint8_t> NOOP_FINGERPRINT(test::SHA256_SIZE, 0U);

    const char ADDR4[] = "192.0.2.1";
    const char ADDR6[] = "2001:db8::1";

    const char cleartext_addr[] = "127.0.0.53";
    const char cleartext_port[] = "53";
    const char tls_port[] = "853";
    const std::vector<std::string> servers = { cleartext_addr };

    test::DNSResponder dns(cleartext_addr, cleartext_port, 250, ns_rcode::ns_r_servfail);
    ASSERT_TRUE(dns.startServer());

    test::DnsTlsFrontend tls(cleartext_addr, tls_port, cleartext_addr, cleartext_port);

    struct TestConfig {
        const std::string mode;
        const bool withWorkingTLS;
        const std::string method;

        std::string asHostName() const {
            return StringPrintf("%s.%s.%s.",
                                mode.c_str(),
                                withWorkingTLS ? "tlsOn" : "tlsOff",
                                method.c_str());
        }
    } testConfigs[]{
        {OFF,           false, GETHOSTBYNAME},
        {OPPORTUNISTIC, false, GETHOSTBYNAME},
        {STRICT,        false, GETHOSTBYNAME},
        {OFF,           true,  GETHOSTBYNAME},
        {OPPORTUNISTIC, true,  GETHOSTBYNAME},
        {STRICT,        true,  GETHOSTBYNAME},
        {OFF,           false, GETADDRINFO},
        {OPPORTUNISTIC, false, GETADDRINFO},
        {STRICT,        false, GETADDRINFO},
        {OFF,           true,  GETADDRINFO},
        {OPPORTUNISTIC, true,  GETADDRINFO},
        {STRICT,        true,  GETADDRINFO},
        {OFF,           false, GETADDRINFOFORNET},
        {OPPORTUNISTIC, false, GETADDRINFOFORNET},
        {STRICT,        false, GETADDRINFOFORNET},
        {OFF,           true,  GETADDRINFOFORNET},
        {OPPORTUNISTIC, true,  GETADDRINFOFORNET},
        {STRICT,        true,  GETADDRINFOFORNET},
    };

    for (const auto& config : testConfigs) {
        const std::string testHostName = config.asHostName();
        SCOPED_TRACE(testHostName);

        // Don't tempt test bugs due to caching.
        const char* host_name = testHostName.c_str();
        dns.addMapping(host_name, ns_type::ns_t_a, ADDR4);
        dns.addMapping(host_name, ns_type::ns_t_aaaa, ADDR6);

        if (config.withWorkingTLS) ASSERT_TRUE(tls.startServer());

        if (config.mode == OFF) {
            ASSERT_TRUE(SetResolversForNetwork(
                    servers, mDefaultSearchDomains,  mDefaultParams_Binder));
        } else if (config.mode == OPPORTUNISTIC) {
            ASSERT_TRUE(SetResolversWithTls(
                    servers, mDefaultSearchDomains, mDefaultParams_Binder, "", {}));
            // Wait for validation to complete.
            if (config.withWorkingTLS) EXPECT_TRUE(tls.waitForQueries(1, 5000));
        } else if (config.mode == STRICT) {
            // We use the existence of fingerprints to trigger strict mode,
            // rather than hostname validation.
            const auto& fingerprint =
                    (config.withWorkingTLS) ? tls.fingerprint() : NOOP_FINGERPRINT;
            ASSERT_TRUE(SetResolversWithTls(
                    servers, mDefaultSearchDomains, mDefaultParams_Binder, "",
                    { base64Encode(fingerprint) }));
            // Wait for validation to complete.
            if (config.withWorkingTLS) EXPECT_TRUE(tls.waitForQueries(1, 5000));
        } else {
            FAIL() << "Unsupported Private DNS mode: " << config.mode;
        }

        const int tlsQueriesBefore = tls.queries();

        const hostent* h_result = nullptr;
        ScopedAddrinfo ai_result;

        if (config.method == GETHOSTBYNAME) {
            ASSERT_EQ(0, setNetworkForResolv(BYPASS_NETID));
            h_result = gethostbyname(host_name);

            EXPECT_EQ(1U, GetNumQueriesForType(dns, ns_type::ns_t_a, host_name));
            ASSERT_FALSE(h_result == nullptr);
            ASSERT_EQ(4, h_result->h_length);
            ASSERT_FALSE(h_result->h_addr_list[0] == nullptr);
            EXPECT_EQ(ADDR4, ToString(h_result));
            EXPECT_TRUE(h_result->h_addr_list[1] == nullptr);
        } else if (config.method == GETADDRINFO) {
            ASSERT_EQ(0, setNetworkForResolv(BYPASS_NETID));
            ai_result = safe_getaddrinfo(host_name, nullptr, nullptr);
            EXPECT_TRUE(ai_result != nullptr);

            EXPECT_LE(1U, GetNumQueries(dns, host_name));
            // Could be A or AAAA
            const std::string result_str = ToString(ai_result);
            EXPECT_TRUE(result_str == ADDR4 || result_str == ADDR6)
                << ", result_str='" << result_str << "'";
        } else if (config.method == GETADDRINFOFORNET) {
            addrinfo* raw_ai_result = nullptr;
            EXPECT_EQ(0, android_getaddrinfofornet(host_name, nullptr, nullptr, BYPASS_NETID,
                                                   MARK_UNSET, &raw_ai_result));
            ai_result.reset(raw_ai_result);

            EXPECT_LE(1U, GetNumQueries(dns, host_name));
            // Could be A or AAAA
            const std::string result_str = ToString(ai_result);
            EXPECT_TRUE(result_str == ADDR4 || result_str == ADDR6)
                << ", result_str='" << result_str << "'";
        } else {
            FAIL() << "Unsupported query method: " << config.method;
        }

        const int tlsQueriesAfter = tls.queries();
        EXPECT_EQ(0, tlsQueriesAfter - tlsQueriesBefore);

        // Clear per-process resolv netid.
        ASSERT_EQ(0, setNetworkForResolv(NETID_UNSET));
        tls.stopServer();
        dns.clearQueries();
    }

    dns.stopServer();
}

TEST_F(ResolverTest, StrictMode_NoTlsServers) {
    const std::vector<uint8_t> NOOP_FINGERPRINT(test::SHA256_SIZE, 0U);
    const char cleartext_addr[] = "127.0.0.53";
    const char cleartext_port[] = "53";
    const std::vector<std::string> servers = { cleartext_addr };

    test::DNSResponder dns(cleartext_addr, cleartext_port, 250, ns_rcode::ns_r_servfail);
    const char* host_name = "strictmode.notlsips.example.com.";
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.4");
    dns.addMapping(host_name, ns_type::ns_t_aaaa, "::1.2.3.4");
    ASSERT_TRUE(dns.startServer());

    ASSERT_TRUE(SetResolversWithTls(
            servers, mDefaultSearchDomains, mDefaultParams_Binder,
            {}, "", { base64Encode(NOOP_FINGERPRINT) }));

    addrinfo* ai_result = nullptr;
    EXPECT_NE(0, getaddrinfo(host_name, nullptr, nullptr, &ai_result));
    EXPECT_EQ(0U, GetNumQueries(dns, host_name));
}
