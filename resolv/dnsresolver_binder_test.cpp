/*
 * Copyright 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * binder_test.cpp - unit tests for netd binder RPCs.
 */

#include <vector>

#include <android-base/strings.h>
#include <android/net/IDnsResolver.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <gtest/gtest.h>
#include <netdb.h>

#include "tests/BaseTestMetricsListener.h"
#include "tests/TestMetrics.h"

#include "Stopwatch.h"
#include "dns_responder.h"
#include "dns_responder_client.h"

using android::IBinder;
using android::IServiceManager;
using android::ProcessState;
using android::sp;
using android::String16;
using android::net::IDnsResolver;
using android::net::metrics::INetdEventListener;
using android::net::metrics::TestOnDnsEvent;

// TODO: make this dynamic and stop depending on implementation details.
// Sync from TEST_NETID in dns_responder_client.cpp as resolver_test.cpp does.
static const int TEST_NETID = 30;

class DnsResolverBinderTest : public ::testing::Test {
  public:
    DnsResolverBinderTest() {
        sp<IServiceManager> sm = android::defaultServiceManager();
        sp<IBinder> binder = sm->getService(String16("dnsresolver"));
        if (binder != nullptr) {
            mDnsResolver = android::interface_cast<IDnsResolver>(binder);
        }
    }

    void SetUp() override { ASSERT_NE(nullptr, mDnsResolver.get()); }

  protected:
    sp<IDnsResolver> mDnsResolver;
};

class TimedOperation : public Stopwatch {
  public:
    explicit TimedOperation(const std::string& name) : mName(name) {}
    virtual ~TimedOperation() { fprintf(stderr, "    %s: %6.1f ms\n", mName.c_str(), timeTaken()); }

  private:
    std::string mName;
};

TEST_F(DnsResolverBinderTest, IsAlive) {
    TimedOperation t("isAlive RPC");
    bool isAlive = false;
    mDnsResolver->isAlive(&isAlive);
    ASSERT_TRUE(isAlive);
}

TEST_F(DnsResolverBinderTest, EventListener_onDnsEvent) {
    // The test configs are used to trigger expected events. The expected results are defined in
    // expectedResults.
    static const struct TestConfig {
        std::string hostname;
        int returnCode;
    } testConfigs[] = {
            {"hi", 0 /*success*/},
            {"nonexistent", EAI_NODATA},
    };

    // The expected results define expected event content for test verification.
    static const std::vector<TestOnDnsEvent::TestResult> expectedResults = {
            {TEST_NETID, INetdEventListener::EVENT_GETADDRINFO, 0 /*success*/, 1, "hi", "1.2.3.4"},
            {TEST_NETID, INetdEventListener::EVENT_GETADDRINFO, EAI_NODATA, 0, "nonexistent", ""},
    };

    // Start the Binder thread pool.
    // TODO: Consider doing this once if there has another event listener unit test.
    android::ProcessState::self()->startThreadPool();

    // Setup network.
    // TODO: Setup device configuration and DNS responser server as resolver test does.
    // Currently, leave DNS related configuration in this test because only it needs DNS
    // client-server testing environment.
    DnsResponderClient dnsClient;
    dnsClient.SetUp();

    // Setup DNS responder server.
    constexpr char listen_addr[] = "127.0.0.3";
    constexpr char listen_srv[] = "53";
    test::DNSResponder dns(listen_addr, listen_srv, 250, ns_rcode::ns_r_servfail);
    dns.addMapping("hi.example.com.", ns_type::ns_t_a, "1.2.3.4");
    ASSERT_TRUE(dns.startServer());

    // Setup DNS configuration.
    const std::vector<std::string> test_servers = {listen_addr};
    std::vector<std::string> test_domains = {"example.com"};
    std::vector<int> test_params = {300 /*sample_validity*/, 25 /*success_threshold*/,
                                    8 /*min_samples*/, 8 /*max_samples*/};
    ASSERT_TRUE(dnsClient.SetResolversForNetwork(test_servers, test_domains, test_params));
    dns.clearQueries();

    // Register event listener.
    TestOnDnsEvent* testOnDnsEvent = new TestOnDnsEvent(expectedResults);
    android::binder::Status status = mDnsResolver->registerEventListener(
            android::interface_cast<INetdEventListener>(testOnDnsEvent));
    ASSERT_TRUE(status.isOk()) << status.exceptionMessage();

    // DNS queries.
    // Once all expected events of expectedResults are received by the listener. The unit test will
    // be notified and the verified flag Event::onDnsEvent of class TestOnDnsEvent will be set.
    auto& cv = testOnDnsEvent->getCv();
    auto& cvMutex = testOnDnsEvent->getCvMutex();
    {
        std::unique_lock lock(cvMutex);

        for (const auto& config : testConfigs) {
            SCOPED_TRACE(config.hostname);

            addrinfo* result = nullptr;
            addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM};
            int status = getaddrinfo(config.hostname.c_str(), nullptr, &hints, &result);
            EXPECT_EQ(config.returnCode, status);

            if (result) freeaddrinfo(result);
        }

        // Wait for receiving expected events.
        EXPECT_EQ(std::cv_status::no_timeout, cv.wait_for(lock, std::chrono::seconds(2)));
    }

    // Verify that all testcases are passed.
    EXPECT_TRUE(testOnDnsEvent->isVerified());

    dnsClient.TearDown();
}