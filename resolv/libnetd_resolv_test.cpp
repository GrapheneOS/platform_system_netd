/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "libnetd_resolv_test"

#include <gtest/gtest.h>

#include <android-base/stringprintf.h>
#include <netdb.h>

#include "dns_responder.h"
#include "netd_resolv/resolv.h"

// TODO: make this dynamic and stop depending on implementation details.
constexpr unsigned int TEST_NETID = 30;

// Specifying 0 in ai_socktype or ai_protocol of struct addrinfo indicates that any type or
// protocol can be returned by getaddrinfo().
constexpr unsigned int ANY = 0;

using android::base::StringPrintf;

namespace android {
namespace net {

// Minimize class ResolverTest to be class TestBase because class TestBase doesn't need all member
// functions of class ResolverTest and class DnsResponderClient.
class TestBase : public ::testing::Test {
  protected:
    void TearDown() {
        resolv_delete_cache_for_net(TEST_NETID);
        resolv_set_nameservers_for_net(TEST_NETID, nullptr, 0, "", nullptr);
    }

    static std::string ToString(const addrinfo* ai) {
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

    const char* mDefaultSearchDomains = "example.com";
    const __res_params mDefaultParams_Binder = {
            .sample_validity = 300,
            .success_threshold = 25,
            .min_samples = 8,
            .max_samples = 8,
            .base_timeout_msec = 100,
    };
};

class GetAddrInfoForNetContextTest : public TestBase {};

TEST_F(GetAddrInfoForNetContextTest, InvalidParameters) {
    struct addrinfo* result = nullptr;
    const android_net_context netcontext = {
            .app_netid = NETID_UNSET,
            .app_mark = MARK_UNSET,
            .dns_netid = NETID_UNSET,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
    };

    // Both null "netcontext" and null "res" of android_getaddrinfofornetcontext() are not tested
    // here because they are checked by assert() without returning any error number.

    // Invalid hostname and servname.
    // Both hostname and servname are null pointers. Expect error number EAI_NONAME.
    int rv = android_getaddrinfofornetcontext(nullptr /*hostname*/, nullptr /*servname*/,
                                              nullptr /*hints*/, &netcontext, &result);
    EXPECT_EQ(EAI_NONAME, rv);
    if (result) {
        freeaddrinfo(result);
        result = nullptr;
    }

    // Invalid hints.
    // These place holders are used to test function call with unrequired parameters.
    // The content is not important because function call returns error directly if
    // there have any unrequired parameter.
    char placeholder_cname[] = "invalid_cname";
    sockaddr placeholder_addr = {};
    addrinfo placeholder_next = {};
    static const struct TestConfig {
        int ai_flags;
        socklen_t ai_addrlen;
        char* ai_canonname;
        struct sockaddr* ai_addr;
        struct addrinfo* ai_next;
        int expected_errorno;  // expected result

        std::string asParameters() const {
            return StringPrintf("0x%x/%u/%s/%p/%p", ai_flags, ai_addrlen,
                                ai_canonname ? ai_canonname : "(null)", (void*) ai_addr,
                                (void*) ai_next);
        }
    } testConfigs[]{
            {0, sizeof(struct in_addr) /*bad*/, nullptr, nullptr, nullptr, EAI_BADHINTS},
            {0, 0, placeholder_cname /*bad*/, nullptr, nullptr, EAI_BADHINTS},
            {0, 0, nullptr, &placeholder_addr /*bad*/, nullptr, EAI_BADHINTS},
            {0, 0, nullptr, nullptr, &placeholder_next /*bad*/, EAI_BADHINTS},
            {AI_ALL /*bad*/, 0, nullptr, nullptr, nullptr, EAI_BADFLAGS},
            {AI_V4MAPPED_CFG /*bad*/, 0, nullptr, nullptr, nullptr, EAI_BADFLAGS},
            {AI_V4MAPPED /*bad*/, 0, nullptr, nullptr, nullptr, EAI_BADFLAGS},
            {AI_DEFAULT /*bad*/, 0, nullptr, nullptr, nullptr, EAI_BADFLAGS},
    };

    for (const auto& config : testConfigs) {
        SCOPED_TRACE(config.asParameters());

        // In current test configuration set, ai_family, ai_protocol and ai_socktype are not
        // checked because other fields cause hints error check failed first.
        const struct addrinfo hints = {
                .ai_flags = config.ai_flags,
                .ai_family = AF_UNSPEC,
                .ai_socktype = ANY,
                .ai_protocol = ANY,
                .ai_addrlen = config.ai_addrlen,
                .ai_canonname = config.ai_canonname,
                .ai_addr = config.ai_addr,
                .ai_next = config.ai_next,
        };

        rv = android_getaddrinfofornetcontext("localhost", nullptr /*servname*/, &hints,
                                              &netcontext, &result);
        EXPECT_EQ(config.expected_errorno, rv);

        if (result) {
            freeaddrinfo(result);
            result = nullptr;
        }
    }
}

TEST_F(GetAddrInfoForNetContextTest, InvalidParameters_Family) {
    const android_net_context netcontext = {
            .app_netid = NETID_UNSET,
            .app_mark = MARK_UNSET,
            .dns_netid = NETID_UNSET,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
    };

    for (int family = 0; family < AF_MAX; ++family) {
        if (family == AF_UNSPEC || family == AF_INET || family == AF_INET6) {
            continue;  // skip supported family
        }
        SCOPED_TRACE(StringPrintf("family: %d", family));

        struct addrinfo* result = nullptr;
        const struct addrinfo hints = {
                .ai_family = family,  // unsupported family
        };

        int rv = android_getaddrinfofornetcontext("localhost", nullptr /*servname*/, &hints,
                                                  &netcontext, &result);
        EXPECT_EQ(EAI_FAMILY, rv);

        if (result) freeaddrinfo(result);
    }
}

TEST_F(GetAddrInfoForNetContextTest, InvalidParameters_MeaningfulSocktypeAndProtocolCombination) {
    const android_net_context netcontext = {
            .app_netid = NETID_UNSET,
            .app_mark = MARK_UNSET,
            .dns_netid = NETID_UNSET,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
    };

    static const int families[] = {PF_INET, PF_INET6, PF_UNSPEC};
    // Skip to test socket type SOCK_RAW in meaningful combination (explore_options[]) of
    // system\netd\resolv\getaddrinfo.cpp. In explore_options[], the socket type SOCK_RAW always
    // comes with protocol ANY which causes skipping meaningful socktype/protocol combination
    // check. So it nerver returns error number EAI_BADHINTS which we want to test in this test
    // case.
    static const int socktypes[] = {SOCK_STREAM, SOCK_DGRAM};

    // If both socktype/protocol are specified, check non-meaningful combination returns
    // expected error number EAI_BADHINTS. See meaningful combination in explore_options[] of
    // system\netd\resolv\getaddrinfo.cpp.
    for (const auto& family : families) {
        for (const auto& socktype : socktypes) {
            for (int protocol = 0; protocol < IPPROTO_MAX; ++protocol) {
                SCOPED_TRACE(StringPrintf("family: %d, socktype: %d, protocol: %d", family,
                                          socktype, protocol));

                // Both socktype/protocol need to be specified.
                if (!socktype || !protocol) continue;

                // Skip meaningful combination in explore_options[] of
                // system\netd\resolv\getaddrinfo.cpp.
                if ((family == AF_INET6 && socktype == SOCK_DGRAM && protocol == IPPROTO_UDP) ||
                    (family == AF_INET6 && socktype == SOCK_STREAM && protocol == IPPROTO_TCP) ||
                    (family == AF_INET && socktype == SOCK_DGRAM && protocol == IPPROTO_UDP) ||
                    (family == AF_INET && socktype == SOCK_STREAM && protocol == IPPROTO_TCP) ||
                    (family == AF_UNSPEC && socktype == SOCK_DGRAM && protocol == IPPROTO_UDP) ||
                    (family == AF_UNSPEC && socktype == SOCK_STREAM && protocol == IPPROTO_TCP)) {
                    continue;
                }

                struct addrinfo* result = nullptr;
                const struct addrinfo hints = {
                        .ai_family = family,
                        .ai_protocol = protocol,
                        .ai_socktype = socktype,
                };

                int rv = android_getaddrinfofornetcontext("localhost", nullptr /*servname*/, &hints,
                                                          &netcontext, &result);
                EXPECT_EQ(EAI_BADHINTS, rv);

                if (result) freeaddrinfo(result);
            }
        }
    }
}

TEST_F(GetAddrInfoForNetContextTest, InvalidParameters_PortNameAndNumber) {
    const android_net_context netcontext = {
            .app_netid = NETID_UNSET,
            .app_mark = MARK_UNSET,
            .dns_netid = NETID_UNSET,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
    };
    constexpr char http_portno[] = "80";
    constexpr char invalid_portno[] = "65536";  // out of valid port range from 0 to 65535
    constexpr char http_portname[] = "http";
    constexpr char invalid_portname[] = "invalid_portname";

    static const struct TestConfig {
        int ai_flags;
        int ai_family;
        int ai_socktype;
        const char* servname;
        int expected_errorno;  // expected result

        std::string asParameters() const {
            return StringPrintf("0x%x/%d/%d/%s", ai_flags, ai_family, ai_socktype,
                                servname ? servname : "(null)");
        }
    } testConfigs[]{
            {0, AF_INET, SOCK_RAW /*bad*/, http_portno, EAI_SERVICE},
            {0, AF_INET6, SOCK_RAW /*bad*/, http_portno, EAI_SERVICE},
            {0, AF_UNSPEC, SOCK_RAW /*bad*/, http_portno, EAI_SERVICE},
            {0, AF_INET, SOCK_RDM /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_INET6, SOCK_RDM /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_UNSPEC, SOCK_RDM /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_INET, SOCK_SEQPACKET /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_INET6, SOCK_SEQPACKET /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_UNSPEC, SOCK_SEQPACKET /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_INET, SOCK_DCCP /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_INET6, SOCK_DCCP /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_UNSPEC, SOCK_DCCP /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_INET, SOCK_PACKET /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_INET6, SOCK_PACKET /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_UNSPEC, SOCK_PACKET /*bad*/, http_portno, EAI_SOCKTYPE},
            {0, AF_INET, ANY, invalid_portno /*bad*/, EAI_SERVICE},
            {0, AF_INET, SOCK_STREAM, invalid_portno /*bad*/, EAI_SERVICE},
            {0, AF_INET, SOCK_DGRAM, invalid_portno /*bad*/, EAI_SERVICE},
            {0, AF_INET6, ANY, invalid_portno /*bad*/, EAI_SERVICE},
            {0, AF_INET6, SOCK_STREAM, invalid_portno /*bad*/, EAI_SERVICE},
            {0, AF_INET6, SOCK_DGRAM, invalid_portno /*bad*/, EAI_SERVICE},
            {0, AF_UNSPEC, ANY, invalid_portno /*bad*/, EAI_SERVICE},
            {0, AF_UNSPEC, SOCK_STREAM, invalid_portno /*bad*/, EAI_SERVICE},
            {0, AF_UNSPEC, SOCK_DGRAM, invalid_portno /*bad*/, EAI_SERVICE},
            {AI_NUMERICSERV, AF_INET, ANY, http_portname /*bad*/, EAI_NONAME},
            {AI_NUMERICSERV, AF_INET, SOCK_STREAM, http_portname /*bad*/, EAI_NONAME},
            {AI_NUMERICSERV, AF_INET, SOCK_DGRAM, http_portname /*bad*/, EAI_NONAME},
            {AI_NUMERICSERV, AF_INET6, ANY, http_portname /*bad*/, EAI_NONAME},
            {AI_NUMERICSERV, AF_INET6, SOCK_STREAM, http_portname /*bad*/, EAI_NONAME},
            {AI_NUMERICSERV, AF_INET6, SOCK_DGRAM, http_portname /*bad*/, EAI_NONAME},
            {AI_NUMERICSERV, AF_UNSPEC, ANY, http_portname /*bad*/, EAI_NONAME},
            {AI_NUMERICSERV, AF_UNSPEC, SOCK_STREAM, http_portname /*bad*/, EAI_NONAME},
            {AI_NUMERICSERV, AF_UNSPEC, SOCK_DGRAM, http_portname /*bad*/, EAI_NONAME},
            {0, AF_INET, ANY, invalid_portname /*bad*/, EAI_SERVICE},
            {0, AF_INET, SOCK_STREAM, invalid_portname /*bad*/, EAI_SERVICE},
            {0, AF_INET, SOCK_DGRAM, invalid_portname /*bad*/, EAI_SERVICE},
            {0, AF_INET6, ANY, invalid_portname /*bad*/, EAI_SERVICE},
            {0, AF_INET6, SOCK_STREAM, invalid_portname /*bad*/, EAI_SERVICE},
            {0, AF_INET6, SOCK_DGRAM, invalid_portname /*bad*/, EAI_SERVICE},
            {0, AF_UNSPEC, ANY, invalid_portname /*bad*/, EAI_SERVICE},
            {0, AF_UNSPEC, SOCK_STREAM, invalid_portname /*bad*/, EAI_SERVICE},
            {0, AF_UNSPEC, SOCK_DGRAM, invalid_portname /*bad*/, EAI_SERVICE},
    };

    for (const auto& config : testConfigs) {
        const std::string testParameters = config.asParameters();
        SCOPED_TRACE(testParameters);

        const struct addrinfo hints = {
                .ai_flags = config.ai_flags,
                .ai_family = config.ai_family,
                .ai_socktype = config.ai_socktype,
        };

        struct addrinfo* result = nullptr;
        int rv = android_getaddrinfofornetcontext("localhost", config.servname, &hints, &netcontext,
                                                  &result);
        EXPECT_EQ(config.expected_errorno, rv);

        if (result) freeaddrinfo(result);
    }
}

// Blocked by aosp/816674 which causes wrong error code EAI_FAIL (4) but EAI_NODATA (7).
// TODO: fix aosp/816674 and add testcases AlphabeticalHostname_NoData back.
/*
TEST_F(GetAddrInfoForNetContextTest, AlphabeticalHostname_NoData) {
    constexpr char listen_addr[] = "127.0.0.3";
    constexpr char listen_srv[] = "53";
    constexpr char v4_host_name[] = "v4only.example.com.";
    constexpr char nonexistent_host_name[] = "nonexistent.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(v4_host_name, ns_type::ns_t_a, "1.2.3.3");
    ASSERT_TRUE(dns.startServer());
    const char* servers[] = {listen_addr};
    ASSERT_EQ(0, resolv_set_nameservers_for_net(TEST_NETID, servers,
                                                sizeof(servers) / sizeof(servers[0]),
                                                mDefaultSearchDomains, &mDefaultParams_Binder));
    dns.clearQueries();

    struct addrinfo* result = nullptr;
    const android_net_context netcontext = {
            .app_netid = TEST_NETID,
            .app_mark = MARK_UNSET,
            .dns_netid = TEST_NETID,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
    };

    // Query nonexistent hostname.
    int rv =
            android_getaddrinfofornetcontext("nonexistent", nullptr, nullptr, &netcontext, &result);
    EXPECT_LE(1U, GetNumQueries(dns, nonexistent_host_name));
    EXPECT_TRUE(result == nullptr);
    EXPECT_EQ(EAI_NODATA, rv);

    if (result) {
        freeaddrinfo(result);
        result = nullptr;
    }

    // Want AAAA answer but DNS server has A answer only.
    const addrinfo hints = {.ai_family = AF_INET6};
    rv = android_getaddrinfofornetcontext("v4only", nullptr, &hints, &netcontext, &result);
    EXPECT_LE(1U, GetNumQueries(dns, v4_host_name));
    EXPECT_TRUE(result == nullptr);
    EXPECT_EQ(EAI_NODATA, rv);

    if (result) freeaddrinfo(result);
}
*/

TEST_F(GetAddrInfoForNetContextTest, AlphabeticalHostname) {
    constexpr char listen_addr[] = "127.0.0.3";
    constexpr char listen_srv[] = "53";
    constexpr char host_name[] = "sawadee.example.com.";
    constexpr char v4addr[] = "1.2.3.4";
    constexpr char v6addr[] = "::1.2.3.4";

    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping(host_name, ns_type::ns_t_a, v4addr);
    dns.addMapping(host_name, ns_type::ns_t_aaaa, v6addr);
    ASSERT_TRUE(dns.startServer());
    const char* servers[] = {listen_addr};
    ASSERT_EQ(0, resolv_set_nameservers_for_net(TEST_NETID, servers,
                                                sizeof(servers) / sizeof(servers[0]),
                                                mDefaultSearchDomains, &mDefaultParams_Binder));

    const android_net_context netcontext = {
            .app_netid = TEST_NETID,
            .app_mark = MARK_UNSET,
            .dns_netid = TEST_NETID,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
    };

    static const struct TestConfig {
        int ai_family;
        const std::string expected_addr;
    } testConfigs[]{
            {AF_INET, v4addr},
            {AF_INET6, v6addr},
    };

    for (const auto& config : testConfigs) {
        SCOPED_TRACE(StringPrintf("family: %d", config.ai_family));
        dns.clearQueries();

        struct addrinfo* result = nullptr;
        const struct addrinfo hints = {.ai_family = config.ai_family};
        int rv = android_getaddrinfofornetcontext("sawadee", nullptr, &hints, &netcontext, &result);
        EXPECT_EQ(0, rv);
        EXPECT_TRUE(result != nullptr);
        EXPECT_EQ(1U, GetNumQueries(dns, host_name));
        EXPECT_EQ(config.expected_addr, ToString(result));

        if (result) freeaddrinfo(result);
    }
}

TEST_F(GetAddrInfoForNetContextTest, ServerResponseError) {
    constexpr char listen_addr[] = "127.0.0.3";
    constexpr char listen_srv[] = "53";
    constexpr char host_name[] = "hello.example.com.";

    const android_net_context netcontext = {
            .app_netid = TEST_NETID,
            .app_mark = MARK_UNSET,
            .dns_netid = TEST_NETID,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
    };

    // Only test failure RCODE [1..5] in RFC 1035 section 4.1.1 and skip successful RCODE 0 which
    // means no error.
    // clang-format off
    static const ns_rcode rcodes[] = {ns_rcode::ns_r_formerr,
                                      ns_rcode::ns_r_servfail,
                                      ns_rcode::ns_r_nxdomain,
                                      ns_rcode::ns_r_notimpl,
                                      ns_rcode::ns_r_refused};
    // clang-format on

    for (const auto& rcode : rcodes) {
        SCOPED_TRACE(StringPrintf("rcode: %d", rcode));

        test::DNSResponder dns(listen_addr, listen_srv, 250, rcode /*response specific rcode*/);
        dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.4");
        dns.setResponseProbability(0.0);  // always ignore requests and response preset rcode
        ASSERT_TRUE(dns.startServer());
        const char* servers[] = {listen_addr};
        ASSERT_EQ(0, resolv_set_nameservers_for_net(TEST_NETID, servers,
                                                    sizeof(servers) / sizeof(servers[0]),
                                                    mDefaultSearchDomains, &mDefaultParams_Binder));

        struct addrinfo* result = nullptr;
        const struct addrinfo hints = {.ai_family = AF_UNSPEC};
        int rv = android_getaddrinfofornetcontext(host_name, nullptr, &hints, &netcontext, &result);
        EXPECT_EQ(EAI_NODATA, rv);

        if (result) freeaddrinfo(result);
    }
}

// TODO: Add private DNS server timeout test.
TEST_F(GetAddrInfoForNetContextTest, ServerTimeout) {
    constexpr char listen_addr[] = "127.0.0.3";
    constexpr char listen_srv[] = "53";
    constexpr char host_name[] = "hello.example.com.";
    test::DNSResponder dns(listen_addr, listen_srv, 250, static_cast<ns_rcode>(-1) /*no response*/);
    dns.addMapping(host_name, ns_type::ns_t_a, "1.2.3.4");
    dns.setResponseProbability(0.0);  // always ignore requests and don't response
    ASSERT_TRUE(dns.startServer());
    const char* servers[] = {listen_addr};
    ASSERT_EQ(0, resolv_set_nameservers_for_net(TEST_NETID, servers,
                                                sizeof(servers) / sizeof(servers[0]),
                                                mDefaultSearchDomains, &mDefaultParams_Binder));

    struct addrinfo* result = nullptr;
    const android_net_context netcontext = {
            .app_netid = TEST_NETID,
            .app_mark = MARK_UNSET,
            .dns_netid = TEST_NETID,
            .dns_mark = MARK_UNSET,
            .uid = NET_CONTEXT_INVALID_UID,
    };

    const struct addrinfo hints = {.ai_family = AF_UNSPEC};
    int rv = android_getaddrinfofornetcontext("hello", nullptr, &hints, &netcontext, &result);
    EXPECT_EQ(NETD_RESOLV_TIMEOUT, rv);

    if (result) freeaddrinfo(result);
}

// Local host file function (files_getaddrinfo) is not tested because it only returns a boolean
// (success or failure) without any error number.

// TODO: Add test NULL hostname, or numeric hostname for android_getaddrinfofornetcontext
// TODO: Add test for android_gethostbyaddrfornetcontext and android_gethostbynamefornetcontext.

}  // end of namespace net
}  // end of namespace android
