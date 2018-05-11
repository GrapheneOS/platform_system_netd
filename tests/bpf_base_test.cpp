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

#include <string>

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <cutils/qtaguid.h>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "bpf/BpfUtils.h"

using namespace android::bpf;

using android::base::unique_fd;
using android::netdutils::status::ok;

namespace android {
namespace bpf {

// Use the upper limit of uid to avoid conflict with real app uids. We can't use UID_MAX because
// it's -1, which is INVALID_UID.
constexpr uid_t TEST_UID = UID_MAX - 1;
constexpr uint32_t TEST_TAG = 42;
constexpr int TEST_COUNTERSET = 1;
constexpr int DEFAULT_COUNTERSET = 0;

class BpfBasicTest : public testing::Test {
  protected:
    BpfBasicTest() {}
};

TEST_F(BpfBasicTest, TestCgroupMounted) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    ASSERT_EQ(0, access(CGROUP_ROOT_PATH, R_OK));
    ASSERT_EQ(0, access("/dev/cg2_bpf/cgroup.controllers", R_OK));
}

TEST_F(BpfBasicTest, TestTrafficControllerSetUp) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    ASSERT_EQ(0, access(BPF_EGRESS_PROG_PATH, R_OK));
    ASSERT_EQ(0, access(BPF_INGRESS_PROG_PATH, R_OK));
    ASSERT_EQ(0, access(XT_BPF_INGRESS_PROG_PATH, R_OK));
    ASSERT_EQ(0, access(XT_BPF_EGRESS_PROG_PATH, R_OK));
    ASSERT_EQ(0, access(COOKIE_TAG_MAP_PATH, R_OK));
    ASSERT_EQ(0, access(UID_COUNTERSET_MAP_PATH, R_OK));
    ASSERT_EQ(0, access(UID_STATS_MAP_PATH, R_OK));
    ASSERT_EQ(0, access(TAG_STATS_MAP_PATH, R_OK));
    ASSERT_EQ(0, access(IFACE_INDEX_NAME_MAP_PATH, R_OK));
    ASSERT_EQ(0, access(IFACE_STATS_MAP_PATH, R_OK));
    ASSERT_EQ(0, access(DOZABLE_UID_MAP_PATH, R_OK));
    ASSERT_EQ(0, access(STANDBY_UID_MAP_PATH, R_OK));
    ASSERT_EQ(0, access(POWERSAVE_UID_MAP_PATH, R_OK));
}

TEST_F(BpfBasicTest, TestTagSocket) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    unique_fd cookieTagMap = unique_fd(mapRetrieve(COOKIE_TAG_MAP_PATH, 0));
    ASSERT_LE(0, cookieTagMap);
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    ASSERT_LE(0, sock);
    uint64_t cookie = getSocketCookie(sock);
    ASSERT_NE(NONEXISTENT_COOKIE, cookie);
    ASSERT_EQ(0, qtaguid_tagSocket(sock, TEST_TAG, TEST_UID));
    struct UidTag tagResult;
    ASSERT_EQ(0, findMapEntry(cookieTagMap, &cookie, &tagResult));
    ASSERT_EQ(TEST_UID, tagResult.uid);
    ASSERT_EQ(TEST_TAG, tagResult.tag);
    ASSERT_EQ(0, qtaguid_untagSocket(sock));
    ASSERT_EQ(-1, findMapEntry(cookieTagMap, &cookie, &tagResult));
    ASSERT_EQ(ENOENT, errno);
}

TEST_F(BpfBasicTest, TestChangeCounterSet) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    unique_fd uidCounterSetMap = unique_fd(mapRetrieve(UID_COUNTERSET_MAP_PATH, 0));
    ASSERT_LE(0, uidCounterSetMap);
    ASSERT_EQ(0, qtaguid_setCounterSet(TEST_COUNTERSET, TEST_UID));
    uid_t uid = TEST_UID;
    int counterSetResult;
    ASSERT_EQ(0, findMapEntry(uidCounterSetMap, &uid, &counterSetResult));
    ASSERT_EQ(TEST_COUNTERSET, counterSetResult);
    ASSERT_EQ(0, qtaguid_setCounterSet(DEFAULT_COUNTERSET, TEST_UID));
    ASSERT_EQ(-1, findMapEntry(uidCounterSetMap, &uid, &counterSetResult));
    ASSERT_EQ(ENOENT, errno);
}

TEST_F(BpfBasicTest, TestDeleteTagData) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    unique_fd uidStatsMap = unique_fd(mapRetrieve(UID_STATS_MAP_PATH, 0));
    ASSERT_LE(0, uidStatsMap);
    unique_fd tagStatsMap = unique_fd(mapRetrieve(TAG_STATS_MAP_PATH, 0));
    ASSERT_LE(0, tagStatsMap);

    StatsKey key = {.uid = TEST_UID, .tag = TEST_TAG, .counterSet = TEST_COUNTERSET,
                    .ifaceIndex = 1};
    StatsValue statsMapValue = {.rxPackets = 1, .rxBytes = 100};
    EXPECT_EQ(0, writeToMapEntry(tagStatsMap, &key, &statsMapValue, BPF_ANY));
    key.tag = 0;
    EXPECT_EQ(0, writeToMapEntry(uidStatsMap, &key, &statsMapValue, BPF_ANY));
    ASSERT_EQ(0, qtaguid_deleteTagData(0, TEST_UID));
    ASSERT_EQ(-1, findMapEntry(uidStatsMap, &key, &statsMapValue));
    ASSERT_EQ(ENOENT, errno);
    key.tag = TEST_TAG;
    ASSERT_EQ(-1, findMapEntry(tagStatsMap, &key, &statsMapValue));
    ASSERT_EQ(ENOENT, errno);
}

}
}
