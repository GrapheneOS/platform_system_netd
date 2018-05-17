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
#include "FirewallController.h"
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
constexpr uid_t TEST_UID2 = 54321;
constexpr uid_t TEST_UID3 = 98765;
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
    unique_fd mFakeDozableUidMap;
    unique_fd mFakeStandbyUidMap;
    unique_fd mFakePowerSaveUidMap;

    void SetUp() {
        std::lock_guard<std::mutex> ownerGuard(mTc.mOwnerMatchMutex);
        std::lock_guard<std::mutex> statsGuard(mTc.mDeleteStatsMutex);
        SKIP_IF_BPF_NOT_SUPPORTED;

        mFakeCookieTagMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(uint64_t),
                                                sizeof(struct UidTag), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeCookieTagMap);

        mFakeUidCounterSetMap = unique_fd(
            createMap(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeUidCounterSetMap);

        mFakeUidStatsMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(struct StatsKey),
                                               sizeof(struct StatsValue), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeUidStatsMap);

        mFakeTagStatsMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(struct StatsKey),
                                               sizeof(struct StatsValue), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeTagStatsMap);

        mFakeDozableUidMap = unique_fd(
            createMap(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeDozableUidMap);

        mFakeStandbyUidMap = unique_fd(
            createMap(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeStandbyUidMap);

        mFakePowerSaveUidMap = unique_fd(
            createMap(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakePowerSaveUidMap);
        // Make sure trafficController use the eBPF code path.
        mTc.ebpfSupported = true;

        mTc.mCookieTagMap.reset(mFakeCookieTagMap);
        mTc.mUidCounterSetMap.reset(mFakeUidCounterSetMap);
        mTc.mUidStatsMap.reset(mFakeUidStatsMap);
        mTc.mTagStatsMap.reset(mFakeTagStatsMap);
        mTc.mDozableUidMap.reset(mFakeDozableUidMap);
        mTc.mStandbyUidMap.reset(mFakeStandbyUidMap);
        mTc.mPowerSaveUidMap.reset(mFakePowerSaveUidMap);
    }

    int setUpSocketAndTag(int protocol, uint64_t* cookie, uint32_t tag, uid_t uid) {
        int sock = socket(protocol, SOCK_STREAM, 0);
        EXPECT_LE(0, sock);
        *cookie = getSocketCookie(sock);
        EXPECT_NE(NONEXISTENT_COOKIE, *cookie);
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
        uint64_t invalidCookie = NONEXISTENT_COOKIE;
        uint64_t cookie;
        EXPECT_EQ(-1, getNextMapKey(mFakeCookieTagMap, &invalidCookie, &cookie));
    }

    void populateFakeStats(uint64_t cookie, uid_t uid, uint32_t tag, StatsKey* key) {
        UidTag cookieMapkey = {.uid = (uint32_t)uid, .tag = tag};
        EXPECT_EQ(0, writeToMapEntry(mFakeCookieTagMap, &cookie, &cookieMapkey, BPF_ANY));
        *key = {.uid = uid, .tag = tag, .counterSet = TEST_COUNTERSET, .ifaceIndex = 1};
        StatsValue statsMapValue = {.rxPackets = 1, .rxBytes = 100};
        int counterSet = TEST_COUNTERSET;
        EXPECT_EQ(0, writeToMapEntry(mFakeUidCounterSetMap, &uid, &counterSet, BPF_ANY));
        EXPECT_EQ(0, writeToMapEntry(mFakeTagStatsMap, key, &statsMapValue, BPF_ANY));
        key->tag = 0;
        EXPECT_EQ(0, writeToMapEntry(mFakeUidStatsMap, key, &statsMapValue, BPF_ANY));
        // put tag information back to statsKey
        key->tag = tag;
    }

    void checkUidOwnerRuleForChain(ChildChain chain, const unique_fd& targetMap) {
        uint32_t uid = TEST_UID;
        EXPECT_EQ(0, mTc.changeUidOwnerRule(chain, uid, DENY, BLACKLIST));
        uint8_t value;
        EXPECT_EQ(0, findMapEntry(targetMap, &uid, &value));
        EXPECT_EQ((uint8_t)BPF_DROP, value);

        uid = TEST_UID2;
        EXPECT_EQ(0, mTc.changeUidOwnerRule(chain, uid, ALLOW, WHITELIST));
        EXPECT_EQ(0, findMapEntry(targetMap, &uid, &value));
        EXPECT_EQ((uint8_t)BPF_PASS, value);

        EXPECT_EQ(0, mTc.changeUidOwnerRule(chain, uid, DENY, WHITELIST));
        EXPECT_EQ(-1, findMapEntry(targetMap, &uid, &value));
        EXPECT_EQ(ENOENT, errno);

        uid = TEST_UID;
        EXPECT_EQ(0, mTc.changeUidOwnerRule(chain, uid, ALLOW, BLACKLIST));
        EXPECT_EQ(-1, findMapEntry(targetMap, &uid, &value));
        EXPECT_EQ(ENOENT, errno);

        uid = TEST_UID3;
        EXPECT_EQ(-ENOENT, mTc.changeUidOwnerRule(chain, uid, ALLOW, BLACKLIST));
        EXPECT_EQ(-1, findMapEntry(targetMap, &uid, &value));
        EXPECT_EQ(ENOENT, errno);
    }

    void checkEachUidValue(const std::vector<int32_t>& uids, const uint8_t expectValue,
                           const unique_fd& targetMap) {
        uint8_t value;
        for (auto uid : uids) {
            EXPECT_EQ(0, findMapEntry(targetMap, &uid, &value));
            EXPECT_EQ((uint8_t)expectValue, value);
        }
        std::set<uint32_t> uidSet(uids.begin(), uids.end());
        auto checkNoOtherUid = [&uidSet](void *key, const base::unique_fd&) {
            int32_t uid = *(int32_t *)key;
            EXPECT_NE(uidSet.end(), uidSet.find(uid));
            return BPF_CONTINUE;
        };
        uint32_t dummyKey;
        EXPECT_EQ(0, bpfIterateMap(dummyKey, targetMap, checkNoOtherUid));
    }

    void checkUidMapReplace(const std::string& name, const std::vector<int32_t>& uids,
                            const unique_fd& targetMap) {
        bool isWhitelist = true;
        EXPECT_EQ(0, mTc.replaceUidOwnerMap(name, isWhitelist, uids));
        checkEachUidValue(uids, BPF_PASS, targetMap);

        isWhitelist = false;
        EXPECT_EQ(0, mTc.replaceUidOwnerMap(name, isWhitelist, uids));
        checkEachUidValue(uids, BPF_DROP, targetMap);
    }

    void TearDown() {
        mFakeCookieTagMap.reset();
        mFakeUidCounterSetMap.reset();
        mFakeUidStatsMap.reset();
        mFakeTagStatsMap.reset();
    }
};

TEST_F(TrafficControllerTest, TestTagSocketV4) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    uint64_t sockCookie;
    int v4socket = setUpSocketAndTag(AF_INET, &sockCookie, TEST_TAG, TEST_UID);
    expectUidTag(sockCookie, TEST_UID, TEST_TAG);
    ASSERT_EQ(0, mTc.untagSocket(v4socket));
    expectNoTag(sockCookie);
    expectTagMapEmpty();
}

TEST_F(TrafficControllerTest, TestReTagSocket) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    uint64_t sockCookie;
    int v4socket = setUpSocketAndTag(AF_INET, &sockCookie, TEST_TAG, TEST_UID);
    expectUidTag(sockCookie, TEST_UID, TEST_TAG);
    ASSERT_EQ(0, mTc.tagSocket(v4socket, TEST_TAG + 1, TEST_UID + 1));
    expectUidTag(sockCookie, TEST_UID + 1, TEST_TAG + 1);
}

TEST_F(TrafficControllerTest, TestTagTwoSockets) {
    SKIP_IF_BPF_NOT_SUPPORTED;

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
    SKIP_IF_BPF_NOT_SUPPORTED;

    uint64_t sockCookie;
    int v6socket = setUpSocketAndTag(AF_INET6, &sockCookie, TEST_TAG, TEST_UID);
    expectUidTag(sockCookie, TEST_UID, TEST_TAG);
    ASSERT_EQ(0, mTc.untagSocket(v6socket));
    expectNoTag(sockCookie);
    expectTagMapEmpty();
}

TEST_F(TrafficControllerTest, TestTagInvalidSocket) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    int invalidSocket = -1;
    ASSERT_GT(0, mTc.tagSocket(invalidSocket, TEST_TAG, TEST_UID));
    expectTagMapEmpty();
}

TEST_F(TrafficControllerTest, TestUntagInvalidSocket) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    int invalidSocket = -1;
    ASSERT_GT(0, mTc.untagSocket(invalidSocket));
    int v4socket = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GT(0, mTc.untagSocket(v4socket));
    expectTagMapEmpty();
}

TEST_F(TrafficControllerTest, TestSetCounterSet) {
    SKIP_IF_BPF_NOT_SUPPORTED;

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
    SKIP_IF_BPF_NOT_SUPPORTED;

    ASSERT_GT(0, mTc.setCounterSet(COUNTERSETS_LIMIT, TEST_UID));
    uid_t uid = TEST_UID;
    int counterSetResult;
    ASSERT_EQ(-1, findMapEntry(mFakeUidCounterSetMap, &uid, &counterSetResult));
    uid = TEST_UID;
    ASSERT_EQ(-1, getNextMapKey(mFakeUidCounterSetMap, &uid, &counterSetResult));
}

TEST_F(TrafficControllerTest, TestDeleteTagData) {
    SKIP_IF_BPF_NOT_SUPPORTED;

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
    StatsValue statsMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey, &statsMapResult));
    tagStatsMapKey.tag = 0;
    ASSERT_EQ(0, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey, &statsMapResult));
    ASSERT_EQ((uint64_t)1, statsMapResult.rxPackets);
    ASSERT_EQ((uint64_t)100, statsMapResult.rxBytes);
}

TEST_F(TrafficControllerTest, TestDeleteAllUidData) {
    SKIP_IF_BPF_NOT_SUPPORTED;

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
    StatsValue statsMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey, &statsMapResult));
    ASSERT_EQ(-1, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey, &statsMapResult));
}

TEST_F(TrafficControllerTest, TestDeleteDataWithTwoTags) {
    SKIP_IF_BPF_NOT_SUPPORTED;

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
    StatsValue statsMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey1, &statsMapResult));
    ASSERT_EQ(0, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey2, &statsMapResult));
    ASSERT_EQ((uint64_t)1, statsMapResult.rxPackets);
    ASSERT_EQ((uint64_t)100, statsMapResult.rxBytes);
}

TEST_F(TrafficControllerTest, TestDeleteDataWithTwoUids) {
    SKIP_IF_BPF_NOT_SUPPORTED;

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
    StatsValue statsMapResult;
    ASSERT_EQ(-1, findMapEntry(mFakeTagStatsMap, &tagStatsMapKey2, &statsMapResult));
    tagStatsMapKey2.tag = 0;
    ASSERT_EQ(-1, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey2, &statsMapResult));
    tagStatsMapKey1.tag = 0;
    ASSERT_EQ(0, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey1, &statsMapResult));
    ASSERT_EQ((uint64_t)1, statsMapResult.rxPackets);
    ASSERT_EQ((uint64_t)100, statsMapResult.rxBytes);

    // Delete the stats of the other uid.
    ASSERT_EQ(0, mTc.deleteTagData(0, uid1));
    ASSERT_EQ(-1, findMapEntry(mFakeUidStatsMap, &tagStatsMapKey1, &statsMapResult));
}

TEST_F(TrafficControllerTest, TestUpdateOwnerMapEntry) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    uint32_t uid = TEST_UID;
    ASSERT_EQ(0, mTc.updateOwnerMapEntry(mFakeDozableUidMap, uid, DENY, BLACKLIST));
    uint8_t value;
    ASSERT_EQ(0, findMapEntry(mFakeDozableUidMap, &uid, &value));
    ASSERT_EQ((uint8_t)BPF_DROP, value);

    uid = TEST_UID2;
    ASSERT_EQ(0, mTc.updateOwnerMapEntry(mFakeDozableUidMap, uid, ALLOW, WHITELIST));
    ASSERT_EQ(0, findMapEntry(mFakeDozableUidMap, &uid, &value));
    ASSERT_EQ((uint8_t)BPF_PASS, value);

    ASSERT_EQ(0, mTc.updateOwnerMapEntry(mFakeDozableUidMap, uid, DENY, WHITELIST));
    ASSERT_EQ(-1, findMapEntry(mFakeDozableUidMap, &uid, &value));
    ASSERT_EQ(ENOENT, errno);

    uid = TEST_UID;
    ASSERT_EQ(0, mTc.updateOwnerMapEntry(mFakeDozableUidMap, uid, ALLOW, BLACKLIST));
    ASSERT_EQ(-1, findMapEntry(mFakeDozableUidMap, &uid, &value));
    ASSERT_EQ(ENOENT, errno);

    uid = TEST_UID3;
    ASSERT_EQ(-ENOENT, mTc.updateOwnerMapEntry(mFakeDozableUidMap, uid, ALLOW, BLACKLIST));
    ASSERT_EQ(-1, findMapEntry(mFakeDozableUidMap, &uid, &value));
    ASSERT_EQ(ENOENT, errno);
}

TEST_F(TrafficControllerTest, TestChangeUidOwnerRule) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    checkUidOwnerRuleForChain(DOZABLE, mFakeDozableUidMap);
    checkUidOwnerRuleForChain(STANDBY, mFakeStandbyUidMap);
    checkUidOwnerRuleForChain(POWERSAVE, mFakePowerSaveUidMap);
    ASSERT_EQ(-EINVAL, mTc.changeUidOwnerRule(NONE, TEST_UID, ALLOW, WHITELIST));
    ASSERT_EQ(-EINVAL, mTc.changeUidOwnerRule(INVALID_CHAIN, TEST_UID, ALLOW, WHITELIST));
}

TEST_F(TrafficControllerTest, TestReplaceUidOwnerMap) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    std::vector<int32_t> uids = {TEST_UID, TEST_UID2, TEST_UID3};
    checkUidMapReplace("fw_dozable", uids, mFakeDozableUidMap);
    checkUidMapReplace("fw_standby", uids, mFakeStandbyUidMap);
    checkUidMapReplace("fw_powersave", uids, mFakePowerSaveUidMap);
    ASSERT_EQ(-EINVAL, mTc.replaceUidOwnerMap("unknow", true, uids));
}

}  // namespace net
}  // namespace android
