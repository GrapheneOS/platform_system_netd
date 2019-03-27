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
 * ClatUtilsTest.cpp - unit tests for ClatUtils.cpp
 */

#include <gtest/gtest.h>

#include "ClatUtils.h"

#include <linux/if_arp.h>

#include "bpf/BpfUtils.h"
#include "netdbpf/bpf_shared.h"

namespace android {
namespace net {

class ClatUtilsTest : public ::testing::Test {
  public:
    void SetUp() {}
};

TEST_F(ClatUtilsTest, HardwareAddressTypeOfNonExistingIf) {
    EXPECT_EQ(-ENODEV, hardwareAddressType("not_existing_if"));
}

TEST_F(ClatUtilsTest, HardwareAddressTypeOfLoopback) {
    EXPECT_EQ(ARPHRD_LOOPBACK, hardwareAddressType("lo"));
}

// If wireless 'wlan0' interface exists it should be Ethernet.
TEST_F(ClatUtilsTest, HardwareAddressTypeOfWireless) {
    int type = hardwareAddressType("wlan0");
    if (type == -ENODEV) return;

    EXPECT_EQ(ARPHRD_ETHER, type);
}

// If cellular 'rmnet_data0' interface exists it should
// *probably* not be Ethernet and instead be RawIp.
TEST_F(ClatUtilsTest, HardwareAddressTypeOfCellular) {
    int type = hardwareAddressType("rmnet_data0");
    if (type == -ENODEV) return;

    EXPECT_NE(ARPHRD_ETHER, type);

    // ARPHRD_RAWIP is 530 on some pre-4.14 Qualcomm devices.
    if (type == 530) return;

    EXPECT_EQ(ARPHRD_RAWIP, type);
}

TEST_F(ClatUtilsTest, GetClatMapFd) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    base::unique_fd ufd(getClatMapFd());
    EXPECT_LE(3, ufd);  // 0,1,2 - stdin/out/err, thus 3 <= fd
}

TEST_F(ClatUtilsTest, GetClatRawIpProgFd) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    base::unique_fd ufd(getClatProgFd(false));
    EXPECT_LE(3, ufd);
}

TEST_F(ClatUtilsTest, GetClatEtherProgFd) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    base::unique_fd ufd(getClatProgFd(true));
    EXPECT_LE(3, ufd);
}

}  // namespace net
}  // namespace android
