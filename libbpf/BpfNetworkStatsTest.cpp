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

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <inttypes.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <netdutils/MockSyscalls.h>
#include "bpf/BpfNetworkStats.h"
#include "bpf/BpfUtils.h"

using namespace android::bpf;

using ::testing::_;
using ::testing::ByMove;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::Test;

namespace android {
namespace bpf {

using base::unique_fd;
using netdutils::status::ok;

constexpr int TEST_MAP_SIZE = 10;
constexpr uid_t TEST_UID1 = 10086;
constexpr uid_t TEST_UID2 = 12345;
constexpr uint32_t TEST_TAG = 42;
constexpr int TEST_COUNTERSET0 = 0;
constexpr int TEST_COUNTERSET1 = 1;
constexpr const int COUNTERSETS_LIMIT = 2;
constexpr uint64_t TEST_BYTES0 = 1000;
constexpr uint64_t TEST_BYTES1 = 2000;
constexpr uint64_t TEST_PACKET0 = 100;
constexpr uint64_t TEST_PACKET1 = 200;
constexpr const char* IFACE_NAME1 = "lo";
constexpr const char* IFACE_NAME2 = "wlan0";
constexpr const char* IFACE_NAME3 = "rmnet_data0";
constexpr uint32_t IFACE_INDEX1 = 1;
constexpr uint32_t IFACE_INDEX2 = 2;
constexpr uint32_t IFACE_INDEX3 = 3;
constexpr uint32_t UNKNOWN_IFACE = 0;

class BpfNetworkStatsHelperTest : public testing::Test {
  protected:
    BpfNetworkStatsHelperTest() {}
    unique_fd mFakeCookieTagMap;
    unique_fd mFakeUidStatsMap;
    unique_fd mFakeTagStatsMap;
    unique_fd mFakeIfaceIndexNameMap;
    unique_fd mFakeIfaceStatsMap;

    void SetUp() {
        mFakeCookieTagMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(uint64_t),
                                                sizeof(struct UidTag), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeCookieTagMap);

        mFakeUidStatsMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(struct StatsKey),
                                               sizeof(struct StatsValue), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeUidStatsMap);

        mFakeTagStatsMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(struct StatsKey),
                                               sizeof(struct StatsValue), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeTagStatsMap);

        mFakeIfaceIndexNameMap =
            unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(uint32_t), IFNAMSIZ, TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeIfaceIndexNameMap);

        mFakeIfaceStatsMap = unique_fd(createMap(BPF_MAP_TYPE_HASH, sizeof(uint32_t),
                                                 sizeof(struct StatsValue), TEST_MAP_SIZE, 0));
        ASSERT_LE(0, mFakeIfaceStatsMap);
    }

    void TearDown() {
        mFakeCookieTagMap.reset();
        mFakeUidStatsMap.reset();
        mFakeTagStatsMap.reset();
        mFakeIfaceIndexNameMap.reset();
        mFakeIfaceStatsMap.reset();
    }

    void expectUidTag(uint64_t cookie, uid_t uid, uint32_t tag) {
        struct UidTag tagResult;
        EXPECT_EQ(0, findMapEntry(mFakeCookieTagMap, &cookie, &tagResult));
        EXPECT_EQ(uid, tagResult.uid);
        EXPECT_EQ(tag, tagResult.tag);
    }

    void populateFakeStats(uid_t uid, uint32_t tag, uint32_t ifaceIndex, uint32_t counterSet,
                           StatsValue* value, const base::unique_fd& map_fd) {
        StatsKey key = {
            .uid = (uint32_t)uid, .tag = tag, .counterSet = counterSet, .ifaceIndex = ifaceIndex};
        EXPECT_EQ(0, writeToMapEntry(map_fd, &key, value, BPF_ANY));
    }

    void updateIfaceMap(const char* ifaceName, uint32_t ifaceIndex) {
        char iface[IFNAMSIZ];
        strlcpy(iface, ifaceName, IFNAMSIZ);
        EXPECT_EQ(0, writeToMapEntry(mFakeIfaceIndexNameMap, &ifaceIndex, iface, BPF_ANY));
    }

    void expectStatsEqual(const StatsValue& target, const Stats& result) {
        EXPECT_EQ(target.rxPackets, result.rxPackets);
        EXPECT_EQ(target.rxBytes, result.rxBytes);
        EXPECT_EQ(target.txPackets, result.txPackets);
        EXPECT_EQ(target.txBytes, result.txBytes);
    }

    void expectStatsLineEqual(const StatsValue target, const char* iface, uint32_t uid,
                              int counterSet, uint32_t tag, const stats_line& result) {
        EXPECT_EQ(0, strcmp(iface, result.iface));
        EXPECT_EQ(uid, (uint32_t)result.uid);
        EXPECT_EQ(counterSet, result.set);
        EXPECT_EQ(tag, (uint32_t)result.tag);
        EXPECT_EQ(target.rxPackets, (uint64_t)result.rxPackets);
        EXPECT_EQ(target.rxBytes, (uint64_t)result.rxBytes);
        EXPECT_EQ(target.txPackets, (uint64_t)result.txPackets);
        EXPECT_EQ(target.txBytes, (uint64_t)result.txBytes);
    }
};

// TEST to verify the behavior of bpf map when cocurrent deletion happens when
// iterating the same map.
TEST_F(BpfNetworkStatsHelperTest, TestIterateMapWithDeletion) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    for (int i = 0; i < 5; i++) {
        uint64_t cookie = i + 1;
        struct UidTag tag = {.uid = TEST_UID1, .tag = TEST_TAG};
        EXPECT_EQ(0, writeToMapEntry(mFakeCookieTagMap, &cookie, &tag, BPF_ANY));
    }
    uint64_t curCookie = 0;
    uint64_t nextCookie = 0;
    struct UidTag tagResult;
    EXPECT_EQ(0, getNextMapKey(mFakeCookieTagMap, &curCookie, &nextCookie));
    uint64_t headOfMap = nextCookie;
    curCookie = nextCookie;
    // Find the second entry in the map, then immediately delete it.
    EXPECT_EQ(0, getNextMapKey(mFakeCookieTagMap, &curCookie, &nextCookie));
    EXPECT_EQ(0, deleteMapEntry(mFakeCookieTagMap, &nextCookie));
    // Find the entry that is now immediately after headOfMap, then delete that.
    EXPECT_EQ(0, getNextMapKey(mFakeCookieTagMap, &curCookie, &nextCookie));
    EXPECT_EQ(0, deleteMapEntry(mFakeCookieTagMap, &nextCookie));
    // Attempting to read an entry that has been deleted fails with ENOENT.
    curCookie = nextCookie;
    EXPECT_EQ(-1, findMapEntry(mFakeCookieTagMap, &curCookie, &tagResult));
    EXPECT_EQ(ENOENT, errno);
    // Finding the entry after our deleted entry restarts iteration from the beginning of the map.
    EXPECT_EQ(0, getNextMapKey(mFakeCookieTagMap, &curCookie, &nextCookie));
    EXPECT_EQ(headOfMap, nextCookie);
}

TEST_F(BpfNetworkStatsHelperTest, TestBpfIterateMap) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    for (int i = 0; i < 5; i++) {
        uint64_t cookie = i + 1;
        struct UidTag tag = {.uid = TEST_UID1, .tag = TEST_TAG};
        EXPECT_EQ(0, writeToMapEntry(mFakeCookieTagMap, &cookie, &tag, BPF_ANY));
    }
    int totalCount = 0;
    int totalSum = 0;
    uint64_t dummyCookie;
    auto iterateMapWithoutDeletion = [&totalCount, &totalSum](void* key, const base::unique_fd&) {
        uint64_t cookie = *(uint64_t*)key;
        EXPECT_GE((uint64_t)5, cookie);
        totalCount++;
        totalSum += cookie;
        return BPF_CONTINUE;
    };
    EXPECT_EQ(0, bpfIterateMap(dummyCookie, mFakeCookieTagMap, iterateMapWithoutDeletion));
    EXPECT_EQ(5, totalCount);
    EXPECT_EQ(1 + 2 + 3 + 4 + 5, totalSum);
}

TEST_F(BpfNetworkStatsHelperTest, TestGetUidStatsTotal) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    updateIfaceMap(IFACE_NAME1, IFACE_INDEX1);
    StatsValue value1 = {.rxBytes = TEST_BYTES0,
                         .rxPackets = TEST_PACKET0,
                         .txBytes = TEST_BYTES1,
                         .txPackets = TEST_PACKET1,};
    populateFakeStats(TEST_UID1, 0, IFACE_INDEX1, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID1, 0, IFACE_INDEX1, TEST_COUNTERSET1, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID2, 0, IFACE_INDEX1, TEST_COUNTERSET1, &value1, mFakeUidStatsMap);
    Stats result1 = {};
    ASSERT_EQ(0, bpfGetUidStatsInternal(TEST_UID1, &result1, mFakeUidStatsMap));
    StatsValue uid1Value = {
        .rxBytes = TEST_BYTES0 * 2,
        .rxPackets = TEST_PACKET0 * 2,
        .txBytes = TEST_BYTES1 * 2,
        .txPackets = TEST_PACKET1 * 2,
    };
    expectStatsEqual(uid1Value, result1);

    Stats result2 = {};
    ASSERT_EQ(0, bpfGetUidStatsInternal(TEST_UID2, &result2, mFakeUidStatsMap));
    expectStatsEqual(value1, result2);
    std::vector<stats_line> lines;
    std::vector<std::string> ifaces;
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TAG_ALL, TEST_UID1,
                                                    mFakeUidStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)2, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TAG_ALL, TEST_UID2,
                                                    mFakeUidStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)1, lines.size());
    expectStatsLineEqual(value1, IFACE_NAME1, TEST_UID2, TEST_COUNTERSET1, 0, lines.front());
}

TEST_F(BpfNetworkStatsHelperTest, TestGetIfaceStatsInternal) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    updateIfaceMap(IFACE_NAME1, IFACE_INDEX1);
    updateIfaceMap(IFACE_NAME2, IFACE_INDEX2);
    updateIfaceMap(IFACE_NAME3, IFACE_INDEX3);
    StatsValue value1 = {
        .rxBytes = TEST_BYTES0,
        .rxPackets = TEST_PACKET0,
        .txBytes = TEST_BYTES1,
        .txPackets = TEST_PACKET1,
    };
    StatsValue value2 = {
        .rxBytes = TEST_BYTES1,
        .rxPackets = TEST_PACKET1,
        .txBytes = TEST_BYTES0,
        .txPackets = TEST_PACKET0,
    };
    uint32_t ifaceStatsKey = IFACE_INDEX1;
    EXPECT_EQ(0, writeToMapEntry(mFakeIfaceStatsMap, &ifaceStatsKey, &value1, BPF_ANY));
    ifaceStatsKey = IFACE_INDEX2;
    EXPECT_EQ(0, writeToMapEntry(mFakeIfaceStatsMap, &ifaceStatsKey, &value2, BPF_ANY));
    ifaceStatsKey = IFACE_INDEX3;
    EXPECT_EQ(0, writeToMapEntry(mFakeIfaceStatsMap, &ifaceStatsKey, &value1, BPF_ANY));

    Stats result1 = {};
    ASSERT_EQ(0, bpfGetIfaceStatsInternal(IFACE_NAME1, &result1, mFakeIfaceStatsMap,
                                          mFakeIfaceIndexNameMap));
    expectStatsEqual(value1, result1);
    Stats result2 = {};
    ASSERT_EQ(0, bpfGetIfaceStatsInternal(IFACE_NAME2, &result2, mFakeIfaceStatsMap,
                                          mFakeIfaceIndexNameMap));
    expectStatsEqual(value2, result2);
    Stats totalResult = {};
    ASSERT_EQ(0, bpfGetIfaceStatsInternal(NULL, &totalResult, mFakeIfaceStatsMap,
                                          mFakeIfaceIndexNameMap));
    StatsValue totalValue = {
        .rxBytes = TEST_BYTES0 * 2 + TEST_BYTES1,
        .rxPackets = TEST_PACKET0 * 2 + TEST_PACKET1,
        .txBytes = TEST_BYTES1 * 2 + TEST_BYTES0,
        .txPackets = TEST_PACKET1 * 2 + TEST_PACKET0,
    };
    expectStatsEqual(totalValue, totalResult);
}

TEST_F(BpfNetworkStatsHelperTest, TestGetStatsDetail) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    updateIfaceMap(IFACE_NAME1, IFACE_INDEX1);
    updateIfaceMap(IFACE_NAME2, IFACE_INDEX2);
    StatsValue value1 = {.rxBytes = TEST_BYTES0,
                         .rxPackets = TEST_PACKET0,
                         .txBytes = TEST_BYTES1,
                         .txPackets = TEST_PACKET1,};
    populateFakeStats(TEST_UID1, TEST_TAG, IFACE_INDEX1, TEST_COUNTERSET0, &value1,
                      mFakeTagStatsMap);
    populateFakeStats(TEST_UID1, TEST_TAG, IFACE_INDEX2, TEST_COUNTERSET0, &value1,
                      mFakeTagStatsMap);
    populateFakeStats(TEST_UID1, TEST_TAG + 1, IFACE_INDEX1, TEST_COUNTERSET0, &value1,
                      mFakeTagStatsMap);
    populateFakeStats(TEST_UID2, TEST_TAG, IFACE_INDEX1, TEST_COUNTERSET0, &value1,
                      mFakeTagStatsMap);
    std::vector<stats_line> lines;
    std::vector<std::string> ifaces;
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TAG_ALL, UID_ALL,
                                                    mFakeTagStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)4, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TAG_ALL, TEST_UID1,
                                                    mFakeTagStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)3, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TEST_TAG, TEST_UID1,
                                                    mFakeTagStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)2, lines.size());
    lines.clear();
    ifaces.push_back(std::string(IFACE_NAME1));
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TEST_TAG, TEST_UID1,
                                                    mFakeTagStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)1, lines.size());
    expectStatsLineEqual(value1, IFACE_NAME1, TEST_UID1, TEST_COUNTERSET0, TEST_TAG, lines.front());
}

TEST_F(BpfNetworkStatsHelperTest, TestGetStatsWithSkippedIface) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    updateIfaceMap(IFACE_NAME1, IFACE_INDEX1);
    updateIfaceMap(IFACE_NAME2, IFACE_INDEX2);
    StatsValue value1 = {.rxBytes = TEST_BYTES0,
                         .rxPackets = TEST_PACKET0,
                         .txBytes = TEST_BYTES1,
                         .txPackets = TEST_PACKET1,};
    populateFakeStats(0, 0, 0, COUNTERSETS_LIMIT, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID1, 0, IFACE_INDEX1, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID1, 0, IFACE_INDEX2, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID1, 0, IFACE_INDEX1, TEST_COUNTERSET1, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID2, 0, IFACE_INDEX1, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    std::vector<stats_line> lines;
    std::vector<std::string> ifaces;
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TAG_ALL, UID_ALL,
                                                    mFakeUidStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)4, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TAG_ALL, TEST_UID1,
                                                    mFakeUidStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)3, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TAG_ALL, TEST_UID2,
                                                    mFakeUidStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)1, lines.size());
    expectStatsLineEqual(value1, IFACE_NAME1, TEST_UID2, TEST_COUNTERSET0, 0, lines.front());
    lines.clear();
    ifaces.push_back(std::string(IFACE_NAME1));
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TAG_ALL, TEST_UID1,
                                                    mFakeUidStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)2, lines.size());
}

TEST_F(BpfNetworkStatsHelperTest, TestUnkownIfaceError) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    updateIfaceMap(IFACE_NAME1, IFACE_INDEX1);
    StatsValue value1 = {.rxBytes = TEST_BYTES0 * 20,
                         .rxPackets = TEST_PACKET0,
                         .txBytes = TEST_BYTES1 * 20,
                         .txPackets = TEST_PACKET1,};
    uint32_t ifaceIndex = UNKNOWN_IFACE;
    populateFakeStats(TEST_UID1, 0, ifaceIndex, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID1, 0, IFACE_INDEX1, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    StatsValue value2 = {.rxBytes = TEST_BYTES0 * 40,
                         .rxPackets = TEST_PACKET0,
                         .txBytes = TEST_BYTES1 * 40,
                         .txPackets = TEST_PACKET1,};
    populateFakeStats(TEST_UID1, 0, IFACE_INDEX2, TEST_COUNTERSET0, &value2, mFakeUidStatsMap);
    StatsKey curKey = {.uid = TEST_UID1,
                       .tag = 0,
                       .ifaceIndex = ifaceIndex,
                       .counterSet = TEST_COUNTERSET0};
    char ifname[IFNAMSIZ];
    int64_t unknownIfaceBytesTotal = 0;
    ASSERT_EQ(-ENODEV, getIfaceNameFromMap(mFakeIfaceIndexNameMap, mFakeUidStatsMap, ifaceIndex,
                                           ifname, &curKey, &unknownIfaceBytesTotal));
    ASSERT_EQ(((int64_t)(TEST_BYTES0 * 20 + TEST_BYTES1 * 20)), unknownIfaceBytesTotal);
    curKey.ifaceIndex = IFACE_INDEX2;
    ASSERT_EQ(-ENODEV, getIfaceNameFromMap(mFakeIfaceIndexNameMap, mFakeUidStatsMap, ifaceIndex,
                                           ifname, &curKey, &unknownIfaceBytesTotal));
    ASSERT_EQ(-1, unknownIfaceBytesTotal);
    std::vector<stats_line> lines;
    std::vector<std::string> ifaces;
    // TODO: find a way to test the total of unknown Iface Bytes go above limit.
    ASSERT_EQ(0, parseBpfNetworkStatsDetailInternal(&lines, ifaces, TAG_ALL, UID_ALL,
                                                    mFakeUidStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)1, lines.size());
    expectStatsLineEqual(value1, IFACE_NAME1, TEST_UID1, TEST_COUNTERSET0, 0, lines.front());
}

TEST_F(BpfNetworkStatsHelperTest, TestGetIfaceStatsDetail) {
    SKIP_IF_BPF_NOT_SUPPORTED;

    updateIfaceMap(IFACE_NAME1, IFACE_INDEX1);
    updateIfaceMap(IFACE_NAME2, IFACE_INDEX2);
    updateIfaceMap(IFACE_NAME3, IFACE_INDEX3);
    StatsValue value1 = {
        .rxBytes = TEST_BYTES0,
        .rxPackets = TEST_PACKET0,
        .txBytes = TEST_BYTES1,
        .txPackets = TEST_PACKET1,
    };
    StatsValue value2 = {
        .rxBytes = TEST_BYTES1,
        .rxPackets = TEST_PACKET1,
        .txBytes = TEST_BYTES0,
        .txPackets = TEST_PACKET0,
    };
    uint32_t ifaceStatsKey = IFACE_INDEX1;
    EXPECT_EQ(0, writeToMapEntry(mFakeIfaceStatsMap, &ifaceStatsKey, &value1, BPF_ANY));
    ifaceStatsKey = IFACE_INDEX2;
    EXPECT_EQ(0, writeToMapEntry(mFakeIfaceStatsMap, &ifaceStatsKey, &value2, BPF_ANY));
    ifaceStatsKey = IFACE_INDEX3;
    EXPECT_EQ(0, writeToMapEntry(mFakeIfaceStatsMap, &ifaceStatsKey, &value1, BPF_ANY));
    std::vector<stats_line> lines;
    ASSERT_EQ(0,
              parseBpfNetworkStatsDevInternal(&lines, mFakeIfaceStatsMap, mFakeIfaceIndexNameMap));
    ASSERT_EQ((unsigned long)3, lines.size());
    std::sort(lines.begin(), lines.end(), [](const auto& line1, const auto& line2)-> bool {
        return strcmp(line1.iface, line2.iface) < 0;
    });
    expectStatsLineEqual(value1, IFACE_NAME1, UID_ALL, SET_ALL, TAG_NONE, lines[0]);
    expectStatsLineEqual(value1, IFACE_NAME3, UID_ALL, SET_ALL, TAG_NONE, lines[1]);
    expectStatsLineEqual(value2, IFACE_NAME2, UID_ALL, SET_ALL, TAG_NONE, lines[2]);
}
}  // namespace bpf
}  // namespace android
