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
constexpr int DEFAULT_COUNTERSET = 0;
constexpr const int COUNTERSETS_LIMIT = 2;
constexpr uint64_t TEST_BYTES0 = 1000;
constexpr uint64_t TEST_BYTES1 = 2000;
constexpr uint64_t TEST_BYTES2 = 3000;
constexpr uint64_t TEST_BYTES3 = 4000;
constexpr uint64_t TEST_PACKET0 = 100;
constexpr uint64_t TEST_PACKET1 = 200;
constexpr uint64_t TEST_PACKET2 = 200;
constexpr uint64_t TEST_PACKET3 = 400;
constexpr uint32_t IFACE0 = 1;
constexpr uint32_t IFACE1 = 2;

class BpfNetworkStatsHelperTest : public testing::Test {
  protected:
    BpfNetworkStatsHelperTest() {}
    unique_fd mFakeCookieTagMap;
    unique_fd mFakeUidStatsMap;
    unique_fd mFakeTagStatsMap;

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
    }

    void TearDown() {
        mFakeCookieTagMap.reset();
        mFakeUidStatsMap.reset();
        mFakeTagStatsMap.reset();
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
};

// TEST to verify the behavior of bpf map when cocurrent deletion happens when
// iterating the same map.
TEST_F(BpfNetworkStatsHelperTest, TestIterateMapWithDeletion) {
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

TEST_F(BpfNetworkStatsHelperTest, TestGetUidStatsTotal) {
    StatsValue value1 = {.rxTcpBytes = TEST_BYTES0,
                         .rxTcpPackets = TEST_PACKET0,
                         .txTcpBytes = TEST_BYTES1,
                         .txTcpPackets = TEST_PACKET1,
                         .rxUdpPackets = 0,
                         .rxUdpBytes = 0,
                         .txUdpPackets = 0,
                         .txUdpBytes = 0,
                         .rxOtherBytes = TEST_BYTES2,
                         .rxOtherPackets = TEST_PACKET2,
                         .txOtherBytes = TEST_BYTES3,
                         .txOtherPackets = TEST_PACKET3};
    populateFakeStats(TEST_UID1, 0, IFACE0, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID1, 0, IFACE0, TEST_COUNTERSET1, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID2, 0, IFACE0, TEST_COUNTERSET1, &value1, mFakeUidStatsMap);
    Stats result1 = {};
    ASSERT_EQ(0, bpfGetUidStatsInternal(TEST_UID1, &result1, mFakeUidStatsMap));
    ASSERT_EQ((TEST_PACKET0 + TEST_PACKET2) * 2, result1.rxPackets);
    ASSERT_EQ((TEST_BYTES0 + TEST_BYTES2) * 2, result1.rxBytes);
    ASSERT_EQ((TEST_PACKET1 + TEST_PACKET3) * 2, result1.txPackets);
    ASSERT_EQ((TEST_BYTES1 + TEST_BYTES3) * 2, result1.txBytes);
    Stats result2 = {};
    ASSERT_EQ(0, bpfGetUidStatsInternal(TEST_UID2, &result2, mFakeUidStatsMap));
    ASSERT_EQ((TEST_PACKET0 + TEST_PACKET2), result2.rxPackets);
    ASSERT_EQ((TEST_BYTES0 + TEST_BYTES2), result2.rxBytes);
    ASSERT_EQ((TEST_PACKET1 + TEST_PACKET3), result2.txPackets);
    ASSERT_EQ((TEST_BYTES1 + TEST_BYTES3), result2.txBytes);
    std::vector<stats_line> lines;
    std::vector<std::string> ifaces;
    ASSERT_EQ(0, parseBpfUidStatsDetail(&lines, ifaces, TEST_UID1, mFakeUidStatsMap));
    ASSERT_EQ((unsigned long)2, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfUidStatsDetail(&lines, ifaces, TEST_UID2, mFakeUidStatsMap));
    ASSERT_EQ((unsigned long)1, lines.size());
}

TEST_F(BpfNetworkStatsHelperTest, TestGetIfaceStatsInternal) {
    const char* fakeFilePath = "/data/local/tmp/testIface.txt";
    std::ofstream fakeProcFile(fakeFilePath);
    ASSERT_TRUE(fakeProcFile.is_open());
    fakeProcFile << "Inter-|   Receive                                                |  Transmit  "
                    "                                            \n";
    fakeProcFile << " face |bytes    packets errs drop fifo frame compressed multicast|bytes    "
                    "packets errs drop fifo colls carrier compressed\n";
    fakeProcFile << "    lo:    8308     116    0    0    0     0          0         0     8308    "
                    " 116    0    0    0     0       0          0\n";
    fakeProcFile << "rmnet0: 1507570    2205    0    0    0     0          0         0   489339    "
                    "2237    0    0    0     0       0          0\n";
    fakeProcFile << "  ifb0:   52454     151    0  151    0     0          0         0        0    "
                    "   0    0    0    0     0       0          0\n";
    fakeProcFile << "  ifb1:   52454     151    0  151    0     0          0         0        0    "
                    "   0    0    0    0     0       0          0\n";
    fakeProcFile << "  sit0:       0       0    0    0    0     0          0         0        0    "
                    "   0  148    0    0     0       0          0\n";
    fakeProcFile << "ip6tnl0:       0       0    0    0    0     0          0         0        0   "
                    "    0  151  151    0     0       0          0\n";
    fakeProcFile.close();
    const char* iface = "lo";
    Stats result1 = {};
    ASSERT_EQ(0, bpfGetIfaceStatsInternal(iface, &result1, fakeFilePath));
    EXPECT_EQ(116UL, result1.rxPackets);
    EXPECT_EQ(8308UL, result1.rxBytes);
    EXPECT_EQ(116UL, result1.txPackets);
    EXPECT_EQ(8308UL, result1.txBytes);
    Stats result2 = {};
    const char* iface2 = "rmnet0";
    EXPECT_EQ(0, bpfGetIfaceStatsInternal(iface2, &result2, fakeFilePath));
    EXPECT_EQ(2205UL, result2.rxPackets);
    EXPECT_EQ(1507570UL, result2.rxBytes);
    EXPECT_EQ(2237UL, result2.txPackets);
    EXPECT_EQ(489339UL, result2.txBytes);
}

TEST_F(BpfNetworkStatsHelperTest, TestGetStatsDetail) {
    const char* iface = "lo";
    int ifaceIndex = if_nametoindex(iface);
    ASSERT_LT(0, ifaceIndex);
    StatsValue value1 = {.rxTcpBytes = TEST_BYTES0,
                         .rxTcpPackets = TEST_PACKET0,
                         .txTcpBytes = TEST_BYTES1,
                         .txTcpPackets = TEST_PACKET1,
                         .rxUdpPackets = 0,
                         .rxUdpBytes = 0,
                         .txUdpPackets = 0,
                         .txUdpBytes = 0,
                         .rxOtherBytes = TEST_BYTES2,
                         .rxOtherPackets = TEST_PACKET2,
                         .txOtherBytes = TEST_BYTES3,
                         .txOtherPackets = TEST_PACKET3};
    populateFakeStats(0, 0, 0, COUNTERSETS_LIMIT, &value1, mFakeTagStatsMap);
    populateFakeStats(TEST_UID1, TEST_TAG, ifaceIndex, TEST_COUNTERSET0, &value1, mFakeTagStatsMap);
    populateFakeStats(TEST_UID1, TEST_TAG, ifaceIndex + 1, TEST_COUNTERSET0, &value1,
                      mFakeTagStatsMap);
    populateFakeStats(TEST_UID1, TEST_TAG + 1, ifaceIndex, TEST_COUNTERSET0, &value1,
                      mFakeTagStatsMap);
    populateFakeStats(TEST_UID2, TEST_TAG, ifaceIndex, TEST_COUNTERSET0, &value1, mFakeTagStatsMap);
    std::vector<stats_line> lines;
    std::vector<std::string> ifaces;
    ASSERT_EQ(0, parseBpfTagStatsDetail(&lines, ifaces, TAG_ALL, UID_ALL, mFakeTagStatsMap));
    ASSERT_EQ((unsigned long)4, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfTagStatsDetail(&lines, ifaces, TAG_ALL, TEST_UID1, mFakeTagStatsMap));
    ASSERT_EQ((unsigned long)3, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfTagStatsDetail(&lines, ifaces, TEST_TAG, TEST_UID1, mFakeTagStatsMap));
    ASSERT_EQ((unsigned long)2, lines.size());
    lines.clear();
    ifaces.push_back(std::string(iface));
    ASSERT_EQ(0, parseBpfTagStatsDetail(&lines, ifaces, TEST_TAG, TEST_UID1, mFakeTagStatsMap));
    ASSERT_EQ((unsigned long)1, lines.size());
}

TEST_F(BpfNetworkStatsHelperTest, TestGetStatsWithSkippedIface) {
    const char* iface = "lo";
    int ifaceIndex = if_nametoindex(iface);
    ASSERT_LT(0, ifaceIndex);
    StatsValue value1 = {.rxTcpBytes = TEST_BYTES0,
                         .rxTcpPackets = TEST_PACKET0,
                         .txTcpBytes = TEST_BYTES1,
                         .txTcpPackets = TEST_PACKET1,
                         .rxUdpPackets = 0,
                         .rxUdpBytes = 0,
                         .txUdpPackets = 0,
                         .txUdpBytes = 0,
                         .rxOtherBytes = TEST_BYTES2,
                         .rxOtherPackets = TEST_PACKET2,
                         .txOtherBytes = TEST_BYTES3,
                         .txOtherPackets = TEST_PACKET3};
    populateFakeStats(0, 0, 0, COUNTERSETS_LIMIT, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID1, 0, ifaceIndex, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID1, 0, ifaceIndex + 1, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID1, 0, ifaceIndex, TEST_COUNTERSET1, &value1, mFakeUidStatsMap);
    populateFakeStats(TEST_UID2, 0, ifaceIndex, TEST_COUNTERSET0, &value1, mFakeUidStatsMap);
    std::vector<stats_line> lines;
    std::vector<std::string> ifaces;
    ASSERT_EQ(0, parseBpfUidStatsDetail(&lines, ifaces, -1, mFakeUidStatsMap));
    ASSERT_EQ((unsigned long)4, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfUidStatsDetail(&lines, ifaces, TEST_UID1, mFakeUidStatsMap));
    ASSERT_EQ((unsigned long)3, lines.size());
    lines.clear();
    ASSERT_EQ(0, parseBpfUidStatsDetail(&lines, ifaces, TEST_UID2, mFakeUidStatsMap));
    ASSERT_EQ((unsigned long)1, lines.size());
    lines.clear();
    ifaces.push_back(std::string(iface));
    ASSERT_EQ(0, parseBpfUidStatsDetail(&lines, ifaces, TEST_UID1, mFakeUidStatsMap));
    ASSERT_EQ((unsigned long)2, lines.size());
}

}  // namespace bpf
}  // namespace android
