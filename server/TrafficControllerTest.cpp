/*
 * Copyright 2017 The Android Open Source Project
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
 * TrafficControllerTest.cpp - unit tests for TrafficController.cpp
 */

#include <string>
#include <vector>

#include <fcntl.h>
#include <inttypes.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <netdutils/MockSyscalls.h>
#include "TrafficController.h"
#include "bpf/BpfUtils.h"

using namespace android::bpf;

using ::testing::_;
using ::testing::ByMove;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::Test;

namespace android {
namespace net {

using base::unique_fd;
using netdutils::status::ok;

constexpr int TEST_MAP_SIZE = 10;
constexpr uid_t TEST_UID = 10086;
constexpr uint32_t TEST_TAG = 42;
constexpr int TEST_COUNTERSET = 1;
constexpr int DEFAULT_COUNTERSET = 0;

class TrafficControllerTest : public ::testing::Test {
  protected:
    TrafficControllerTest() {}
    TrafficController mTc;
    unique_fd mFakeCookieTagMap;
    unique_fd mFakeUidCounterSetMap;
    unique_fd mFakeUidStatsMap;
    unique_fd mFakeTagStatsMap;

    void SetUp() {
        mFakeCookieTagMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(uint64_t),
                                                sizeof(struct UidTag), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeCookieTagMap);

        mFakeUidCounterSetMap = unique_fd(
            createMap(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeUidCounterSetMap);

        mFakeUidStatsMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(struct StatsKey),
                                               sizeof(struct Stats), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeUidStatsMap);

        mFakeTagStatsMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(struct StatsKey),
                                               sizeof(struct Stats), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeTagStatsMap);

        // Make sure trafficController use the eBPF code path.
        mTc.ebpfSupported = true;

        mTc.mCookieTagMap.reset(mFakeCookieTagMap);
        mTc.mUidCounterSetMap.reset(mFakeUidCounterSetMap);
        mTc.mUidStatsMap.reset(mFakeUidStatsMap);
        mTc.mTagStatsMap.reset(mFakeTagStatsMap);
    }

    int setUpSocketAndTag(int protocol, uint64_t* cookie, uint32_t tag, uid_t uid) {
        int sock = socket(protocol, SOCK_STREAM, 0);
        EXPECT_LE(0, sock);
        *cookie = getSocketCookie(sock);
        EXPECT_NE(INET_DIAG_NOCOOKIE, *cookie);
        EXPECT_EQ(0, mTc.tagSocket(sock, tag, uid));
        return sock;
    }

    void expectUidTag(uint64_t cookie, uid_t uid, uint32_t tag) {
        struct UidTag tagResult;
        EXPECT_EQ(0, findMapEntry(mFakeCookieTagMap, &cookie, &tagResult));
        EXPECT_EQ(uid, tagResult.uid);
        EXPECT_EQ(tag, tagResult.tag);
    }

    void expectNoTag(uint64_t cookie) {
        struct UidTag tagResult;
        EXPECT_EQ(-1, findMapEntry(mFakeCookieTagMap, &cookie, &tagResult));
    }

    void expectTagMapEmpty() {
        uint64_t invalidCookie = INET_DIAG_NOCOOKIE;
        uint64_t cookie;
        EXPECT_EQ(-1, getNextMapKey(mFakeCookieTagMap, &invalidCookie, &cookie));
    }

    void populateFakeStats(uint64_t cookie, uid_t uid, uint32_t tag, StatsKey* key) {
        UidTag cookieMapkey = {.uid = (uint32_t)uid, .tag = tag};
        EXPECT_EQ(0, writeToMapEntry(mFakeCookieTagMap, &cookie, &cookieMapkey, BPF_ANY));
        *key = {.uid = uid, .tag = tag, .counterSet = TEST_COUNTERSET, .ifaceIndex = 1};
        Stats statsMapValue = {.rxTcpPackets = 1, .rxTcpBytes = 100};
        int counterSet = TEST_COUNTERSET;
        EXPECT_EQ(0, writeToMapEntry(mFakeUidCounterSetMap, &uid, &counterSet, BPF_ANY));
        EXPECT_EQ(0, writeToMapEntry(mFakeTagStatsMap, key, &statsMapValue, BPF_ANY));
        key->tag = 0;
        EXPECT_EQ(0, writeToMapEntry(mFakeUidStatsMap, key, &statsMapValue, BPF_ANY));
    }

    void TearDown() {
        mFakeCookieTagMap.reset();
        mFakeUidCounterSetMap.reset();
        mFakeUidStatsMap.reset();
        mFakeTagStatsMap.reset();
    }
};

TEST_F(TrafficControllerTest, TestTagSocketV4) {
    uint64_t sockCookie;
    int v4socket = setUpSocketAndTag(AF_INET, &sockCookie, TEST_TAG, TEST_UID);
    expectUidTag(sockCookie, TEST_UID, TEST_TAG);
    ASSERT_EQ(0, mTc.untagSocket(v4socket));
    expectNoTag(sockCookie);
    expectTagMapEmpty();
}

TEST_F(TrafficControllerTest, TestReTagSocket) {
    uint64_t sockCookie;
    int v4socket = setUpSocketAndTag(AF_INET, &sockCookie, TEST_TAG, TEST_UID);
    expectUidTag(sockCookie, TEST_UID, TEST_TAG);
    ASSERT_EQ(0, mTc.tagSocket(v4socket, TEST_TAG + 1, TEST_UID + 1));
    expectUidTag(sockCookie, TEST_UID + 1, TEST_TAG + 1);
}

TEST_F(TrafficControllerTest, TestTagTwoSockets) {
    uint64_t sockCookie1;
    uint64_t sockCookie2;
    int v4socket1 = setUpSocketAndTag(AF_INET, &sockCookie1, TEST_TAG, TEST_UID);
    setUpSocketAndTag(AF_INET, &sockCookie2, TEST_TAG, TEST_UID);
    expectUidTag(sockCookie1, TEST_UID, TEST_TAG);
    expectUidTag(sockCookie2, TEST_UID, TEST_TAG);
    ASSERT_EQ(0, mTc.untagSocket(v4socket1));
    expectNoTag(sockCookie1);
    expectUidTag(sockCookie2, TEST_UID, TEST_TAG);
    uint64_t cookieResult;
    ASSERT_EQ(-1, getNextMapKey(mFakeCookieTagMap, &sockCookie2, &cookieResult));
}

TEST_F(TrafficControllerTest, TestTagSocketV6) {
    uint64_t sockCookie;
    int v6socket = setUpSocketAndTag(AF_INET6, &sockCookie, TEST_TAG, TEST_UID);
    expectUidTag(sockCookie, TEST_UID, TEST_TAG);
    ASSERT_EQ(0, mTc.untagSocket(v6socket));
    expectNoTag(sockCookie);
    expectTagMapEmpty();
}

TEST_F(TrafficControllerTest, TestTagInvalidSocket) {
    int invalidSocket = -1;
    ASSERT_GT(0, mTc.tagSocket(invalidSocket, TEST_TAG, TEST_UID));
    expectTagMapEmpty();
}

TEST_F(TrafficControllerTest, TestUntagInvalidSocket) {
    int invalidSocket = -1;
    ASSERT_GT(0, mTc.untagSocket(invalidSocket));
    int v4socket = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GT(0, mTc.untagSocket(v4socket));
    expectTagMapEmpty();
}

TEST_F(TrafficControllerTest, TestSetCounterSet) {
    ASSERT_EQ(0, mTc.setCounterSet(TEST_COUNTERSET, TEST_UID));
    uid_t uid = TEST_UID;
    int counterSetResult;
    ASSERT_EQ(0, findMapEntry(mFakeUidCounterSetMap, &uid, &counterSetResult));
    ASSERT_EQ(TEST_COUNTERSET, counterSetResult);
    ASSERT_EQ(0, mTc.setCounterSet(DEFAULT_COUNTERSET, TEST_UID));
    ASSERT_EQ(-1, findMapEntry(mFakeUidCounterSetMap, &uid, &counterSetResult));
    uid = TEST_UID;
    ASSERT_EQ(-1, getNextMapKey(mFakeUidCounterSetMap, &uid, &counterSetResult));
}

TEST_F(TrafficControllerTest, TestSetInvalidCounterSet) {
    ASSERT_GT(0, mTc.setCounterSet(COUNTERSETS_LIMIT, TEST_UID));
    uid_t uid = TEST_UID;
    int counterSetResult;
    ASSERT_EQ(-1, findMapEntry(mFakeUidCounterSetMap, &uid, &counterSetResult));
    uid = TEST_UID;
    ASSERT_EQ(-1, getNextMapKey(mFakeUidCounterSetMap, &uid, &counterSetResult));
}

TEST_F(TrafficControllerTest, TestDeleteTagData) {
    uint64_t cookie = 1;
    uid_t uid = TEST_UID;
    uint32_t tag = TEST_TAG;
    StatsKey tagStatsMapKey;
    populateFakeStats(cookie, uid, tag, &tagStatsMapKey);
    ASSERT_EQ(0, mTc.deleteTagData(TEST_TAG, TEST_UID));
    UidTag cookieMapkey;
    ASSERT_EQ(-1, findMapEntry(mFakeCookieTagMap, &cookie, &cookieMapkey));
    int counterSetResult;
    ASSERT_EQ(0, findMapEntry(mFakeUidCounterSetMap, &uid, &counterSetResult));
    ASSERT_EQ(TEST_COUNTERSET, counterSetResult);
    Stats statsMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey, &statsMapResult));
    ASSERT_EQ(0, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey, &statsMapResult));
    ASSERT_EQ((uint64_t)1, statsMapResult.rxTcpPackets);
    ASSERT_EQ((uint64_t)100, statsMapResult.rxTcpBytes);
}

TEST_F(TrafficControllerTest, TestDeleteAllUidData) {
    uint64_t cookie = 1;
    uid_t uid = TEST_UID;
    uint32_t tag = TEST_TAG;
    StatsKey tagStatsMapKey;
    populateFakeStats(cookie, uid, tag, &tagStatsMapKey);
    ASSERT_EQ(0, mTc.deleteTagData(0, TEST_UID));
    UidTag cookieMapkey;
    ASSERT_EQ(-1, findMapEntry(mFakeCookieTagMap, &cookie, &cookieMapkey));
    int counterSetResult;
    ASSERT_EQ(-1, findMapEntry(mFakeUidCounterSetMap, &uid, &counterSetResult));
    Stats statsMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey, &statsMapResult));
    ASSERT_EQ(-1, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey, &statsMapResult));
    StatsKey removedStatsKey= {.uid = 0, .tag = 0, .counterSet = COUNTERSETS_LIMIT,
      .ifaceIndex = 0};
    ASSERT_EQ(0, findMapEntry(mFakeUidStatsMap, &removedStatsKey, &statsMapResult));
    ASSERT_EQ((uint64_t)1, statsMapResult.rxTcpPackets);
    ASSERT_EQ((uint64_t)100, statsMapResult.rxTcpBytes);
}

TEST_F(TrafficControllerTest, TestDeleteDataWithTwoTags) {
    uint64_t cookie1 = 1;
    uint64_t cookie2 = 2;
    uid_t uid = TEST_UID;
    uint32_t tag1 = TEST_TAG;
    uint32_t tag2 = TEST_TAG + 1;
    StatsKey tagStatsMapKey1;
    StatsKey tagStatsMapKey2;
    populateFakeStats(cookie1, uid, tag1, &tagStatsMapKey1);
    populateFakeStats(cookie2, uid, tag2, &tagStatsMapKey2);
    ASSERT_EQ(0, mTc.deleteTagData(TEST_TAG, TEST_UID));
    UidTag cookieMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeCookieTagMap, &cookie1, &cookieMapResult));
    ASSERT_EQ(0, findMapEntry(mFakeCookieTagMap, &cookie2, &cookieMapResult));
    ASSERT_EQ(TEST_UID, cookieMapResult.uid);
    ASSERT_EQ(TEST_TAG + 1, cookieMapResult.tag);
    int counterSetResult;
    ASSERT_EQ(0, findMapEntry(mFakeUidCounterSetMap, &uid, &counterSetResult));
    ASSERT_EQ(TEST_COUNTERSET, counterSetResult);
    Stats statsMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey1, &statsMapResult));
    ASSERT_EQ(0, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey2, &statsMapResult));
    ASSERT_EQ((uint64_t)1, statsMapResult.rxTcpPackets);
    ASSERT_EQ((uint64_t)100, statsMapResult.rxTcpBytes);
}

TEST_F(TrafficControllerTest, TestDeleteDataWithTwoUids) {
    uint64_t cookie1 = 1;
    uint64_t cookie2 = 2;
    uid_t uid1 = TEST_UID;
    uid_t uid2 = TEST_UID + 1;
    uint32_t tag = TEST_TAG;
    StatsKey tagStatsMapKey1;
    StatsKey tagStatsMapKey2;
    populateFakeStats(cookie1, uid1, tag, &tagStatsMapKey1);
    populateFakeStats(cookie2, uid2, tag, &tagStatsMapKey2);

    // Delete the stats of one of the uid. Check if it is properly collected by
    // removedStats.
    ASSERT_EQ(0, mTc.deleteTagData(0, uid2));
    UidTag cookieMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeCookieTagMap, &cookie2, &cookieMapResult));
    int counterSetResult;
    ASSERT_EQ(0, findMapEntry(mFakeUidCounterSetMap, &uid1, &counterSetResult));
    ASSERT_EQ(TEST_COUNTERSET, counterSetResult);
    ASSERT_EQ(-1, findMapEntry(mFakeUidCounterSetMap, &uid2, &counterSetResult));
    Stats statsMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey2, &statsMapResult));
    ASSERT_EQ(-1, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey2, &statsMapResult));
    ASSERT_EQ(0, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey1, &statsMapResult));
    ASSERT_EQ((uint64_t)1, statsMapResult.rxTcpPackets);
    ASSERT_EQ((uint64_t)100, statsMapResult.rxTcpBytes);
    StatsKey removedStatsKey= {.uid = 0, .tag = 0, .counterSet = COUNTERSETS_LIMIT,
      .ifaceIndex = 0};
    ASSERT_EQ(0, findMapEntry(mFakeUidStatsMap, &removedStatsKey, &statsMapResult));
    ASSERT_EQ((uint64_t)1, statsMapResult.rxTcpPackets);
    ASSERT_EQ((uint64_t)100, statsMapResult.rxTcpBytes);

    // Delete the stats of the other uid. Check if it is properly added on the
    // previous removedStats data.
    ASSERT_EQ(0, mTc.deleteTagData(0, uid1));
    ASSERT_EQ(-1, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey1, &statsMapResult));
    ASSERT_EQ(0, findMapEntry(mFakeUidStatsMap, &removedStatsKey, &statsMapResult));
    ASSERT_EQ((uint64_t)2, statsMapResult.rxTcpPackets);
    ASSERT_EQ((uint64_t)200, statsMapResult.rxTcpBytes);
}

}  // namespace net
}  // namespace android
