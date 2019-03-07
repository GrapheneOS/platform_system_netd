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
#include <binder/IServiceManager.h>
#include <gtest/gtest.h>

#include "Stopwatch.h"

using android::IBinder;
using android::IServiceManager;
using android::sp;
using android::String16;
using android::net::IDnsResolver;

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