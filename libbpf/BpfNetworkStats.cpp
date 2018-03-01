/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <inttypes.h>
#include <net/if.h>
#include <string.h>
#include <unordered_set>

#include <utils/Log.h>
#include <utils/misc.h>

#include "android-base/file.h"
#include "android-base/strings.h"
#include "android-base/unique_fd.h"
#include "bpf/BpfNetworkStats.h"
#include "bpf/BpfUtils.h"

namespace android {
namespace bpf {

static const char* BPF_IFACE_STATS = "/proc/net/dev";

int bpfGetUidStatsInternal(uid_t uid, Stats* stats, const base::unique_fd& map_fd) {
    struct StatsKey curKey, nextKey;
    curKey = NONEXISTENT_STATSKEY;
    while (bpf::getNextMapKey(map_fd, &curKey, &nextKey) != -1) {
        curKey = nextKey;
        if (curKey.uid == uid) {
            StatsValue statsEntry;
            if (bpf::findMapEntry(map_fd, &curKey, &statsEntry) < 0) {
                return -errno;
            }
            stats->rxPackets += statsEntry.rxPackets;
            stats->txPackets += statsEntry.txPackets;
            stats->rxBytes += statsEntry.rxBytes;
            stats->txBytes += statsEntry.txBytes;
        }
    }
    // Return errno if getNextMapKey return error before hit to the end of the map.
    if (errno != ENOENT) return -errno;
    return 0;
}

int bpfGetUidStats(uid_t uid, Stats* stats) {
    base::unique_fd uidStatsMap(bpf::mapRetrieve(UID_STATS_MAP_PATH, BPF_F_RDONLY));
    if (uidStatsMap < 0) {
        int ret = -errno;
        ALOGE("get map fd failed from %s: %s", UID_STATS_MAP_PATH, strerror(errno));
        return ret;
    }
    return bpfGetUidStatsInternal(uid, stats, uidStatsMap);
}

// TODO: The iface stats read from proc/net/dev contains additional L2 header.
// Need to adjust the byte length read depend on the packets number before
// return.
// Bug: b/72111305
int bpfGetIfaceStatsInternal(const char* iface, Stats* stats, const char* file) {
    std::string content;
    if (!android::base::ReadFileToString(file, &content)) {
        ALOGE("Cannot read iface stats from: %s", file);
        return -errno;
    }
    std::istringstream stream(content);
    for (std::string ifaceLine; std::getline(stream, ifaceLine);) {
        const char* buffer = android::base::Trim(ifaceLine).c_str();
        char cur_iface[IFNAMSIZ];
        uint64_t rxBytes, rxPackets, txBytes, txPackets;
        // Typical iface stats read to parse:
        // interface rxbytes rxpackets errs drop fifo frame compressed multicast txbytes txpackets \
        // errs drop fifo colls carrier compressed
        // lo: 13470483181 57249790 0 0 0 0 0 0 13470483181 57249790 0 0 0 0 0 0
        int matched = sscanf(buffer,
                             "%[^ :]: %" SCNu64 " %" SCNu64
                             " %*lu %*lu %*lu %*lu %*lu %*lu "
                             "%" SCNu64 " %" SCNu64 "",
                             cur_iface, &rxBytes, &rxPackets, &txBytes, &txPackets);
        if (matched >= 5) {
            if (!iface || !strcmp(iface, cur_iface)) {
                stats->rxBytes += rxBytes;
                stats->rxPackets += rxPackets;
                stats->txBytes += txBytes;
                stats->txPackets += txPackets;
            }
        }
    }
    stats->tcpRxPackets = -1;
    stats->tcpTxPackets = -1;

    return 0;
}

int bpfGetIfaceStats(const char* iface, Stats* stats) {
    return bpfGetIfaceStatsInternal(iface, stats, BPF_IFACE_STATS);
}

stats_line populateStatsEntry(const StatsKey& statsKey, const StatsValue& statsEntry,
                              const char* ifname) {
    stats_line newLine;
    strlcpy(newLine.iface, ifname, sizeof(newLine.iface));
    newLine.uid = statsKey.uid;
    newLine.set = statsKey.counterSet;
    newLine.tag = statsKey.tag;
    newLine.rxPackets = statsEntry.rxPackets;
    newLine.txPackets = statsEntry.txPackets;
    newLine.rxBytes = statsEntry.rxBytes;
    newLine.txBytes = statsEntry.txBytes;
    return newLine;
}

int parseBpfUidStatsDetail(std::vector<stats_line>* lines,
                           const std::vector<std::string>& limitIfaces, int limitUid,
                           const base::unique_fd& map_fd) {
    struct StatsKey curKey, nextKey;
    curKey = NONEXISTENT_STATSKEY;
    while (bpf::getNextMapKey(map_fd, &curKey, &nextKey) != -1) {
        curKey = nextKey;
        char ifname[IFNAMSIZ];
        // The data entry in uid map that stores removed uid stats use 0 as the
        // iface. Just skip when seen.
        if (curKey.ifaceIndex == 0) continue;
        // this is relatively expensive, involving a context switch and probably contention on the
        // RTNL lock.
        // TODO: store iface name in map directly instead of ifindex.
        if_indextoname(curKey.ifaceIndex, ifname);
        std::string ifnameStr(ifname);
        if (limitIfaces.size() > 0 &&
            std::find(limitIfaces.begin(), limitIfaces.end(), ifnameStr) == limitIfaces.end()) {
            // Nothing matched; skip this line.
            continue;
        }
        if (limitUid != UID_ALL && limitUid != int(curKey.uid)) continue;
        StatsValue statsEntry;
        if (bpf::findMapEntry(map_fd, &curKey, &statsEntry) < 0) {
            int ret = -errno;
            ALOGE("get map statsEntry failed: %s", strerror(errno));
            return ret;
        }
        lines->push_back(populateStatsEntry(curKey, statsEntry, ifname));
    }
    return 0;
}

int parseBpfTagStatsDetail(std::vector<stats_line>* lines,
                           const std::vector<std::string>& limitIfaces, int limitTag, int limitUid,
                           const base::unique_fd& map_fd) {
    struct StatsKey curKey, nextKey;
    curKey = NONEXISTENT_STATSKEY;
    while (bpf::getNextMapKey(map_fd, &curKey, &nextKey) != -1) {
        curKey = nextKey;
        char ifname[32];
        if (curKey.ifaceIndex == 0) continue;
        if_indextoname(curKey.ifaceIndex, ifname);
        std::string ifnameStr(ifname);
        if (limitIfaces.size() > 0 &&
            std::find(limitIfaces.begin(), limitIfaces.end(), ifnameStr) == limitIfaces.end()) {
            // Nothing matched; skip this line.
            continue;
        }
        if ((limitTag != TAG_ALL && uint32_t(limitTag) != (curKey.tag)) ||
            (limitUid != UID_ALL && uint32_t(limitUid) != curKey.uid))
            continue;
        StatsValue statsEntry;
        if (bpf::findMapEntry(map_fd, &curKey, &statsEntry) < 0) return -errno;
        lines->push_back(populateStatsEntry(curKey, statsEntry, ifname));
    }
    if (errno != ENOENT) return -errno;
    return 0;
}

int parseBpfNetworkStatsDetail(std::vector<stats_line>* lines,
                               const std::vector<std::string>& limitIfaces, int limitTag,
                               int limitUid) {
    base::unique_fd tagStatsMap(bpf::mapRetrieve(TAG_STATS_MAP_PATH, 0));
    int ret = 0;
    if (tagStatsMap < 0) {
        ret = -errno;
        ALOGE("get tagStats map fd failed: %s", strerror(errno));
        return ret;
    }
    ret = parseBpfTagStatsDetail(lines, limitIfaces, limitTag, limitUid, tagStatsMap);
    if (ret) return ret;

    if (limitTag == TAG_ALL) {
        base::unique_fd uidStatsMap(bpf::mapRetrieve(UID_STATS_MAP_PATH, BPF_F_RDONLY));
        if (uidStatsMap < 0) {
            ret = -errno;
            ALOGE("get map fd failed: %s", strerror(errno));
            return ret;
        }
        ret = parseBpfUidStatsDetail(lines, limitIfaces, limitUid, uidStatsMap);
    }
    return ret;
}

uint64_t combineUidTag(const uid_t uid, const uint32_t tag) {
    return (uint64_t)uid << 32 | tag;
}

// This function get called when the system_server decided to clean up the
// tagStatsMap after it gethered the information of taggged socket stats. The
// function go through all the entry in tagStatsMap and remove all the entry
// for which the tag no longer exists.
int cleanStatsMapInternal(const base::unique_fd& cookieTagMap, const base::unique_fd& tagStatsMap) {
    uint64_t curCookie = 0;
    uint64_t nextCookie = 0;
    int res;
    UidTag tmp_uidtag;
    std::unordered_set<uint64_t> uidTagSet;
    StatsKey curKey, nextKey;

    // Find all the uid, tag pair exist in cookieTagMap.
    while (bpf::getNextMapKey(cookieTagMap, &curCookie, &nextCookie) != -1) {
        curCookie = nextCookie;
        res = bpf::findMapEntry(cookieTagMap, &curCookie, &tmp_uidtag);
        if (res < 0) {
            // might be a concurrent delete, continue to check other entries.
            continue;
        }
        uint64_t uidTag = combineUidTag(tmp_uidtag.uid, tmp_uidtag.tag);
        uidTagSet.insert(uidTag);
    }

    // Find all the entries in tagStatsMap where the key is not in the set of
    // uid, tag pairs found above.
    curKey = NONEXISTENT_STATSKEY;
    std::vector<StatsKey> keyList;
    while (bpf::getNextMapKey(tagStatsMap, &curKey, &nextKey) != -1) {
        curKey = nextKey;
        uint64_t uidTag = combineUidTag(curKey.uid, curKey.tag);
        if (uidTagSet.find(uidTag) == uidTagSet.end()) {
            keyList.push_back(curKey);
        }
    }

    // Delete the entries
    int size = keyList.size();
    while (!keyList.empty()) {
        StatsKey key = keyList.back();
        keyList.pop_back();
        res = bpf::deleteMapEntry(tagStatsMap, &key);
        if (res < 0 && errno != ENOENT) {
            res = -errno;
            ALOGE("Failed to delete data(uid=%u, tag=%u): %s\n", key.uid, key.tag, strerror(errno));
            return res;
        }
    }
    ALOGD("finish clean up, %d stats entry cleaned", size);
    return 0;
}

int cleanStatsMap() {
    base::unique_fd cookieTagMap(bpf::mapRetrieve(COOKIE_UID_MAP_PATH, BPF_F_RDONLY));
    int ret = 0;
    if (cookieTagMap < 0) {
        ret = -errno;
        ALOGE("get cookieTag map fd failed: %s", strerror(errno));
        return ret;
    }

    base::unique_fd tagStatsMap(bpf::mapRetrieve(TAG_STATS_MAP_PATH, 0));
    if (tagStatsMap < 0) {
        ret = -errno;
        ALOGE("get tagStats map fd failed: %s", strerror(errno));
        return ret;
    }

    return cleanStatsMapInternal(cookieTagMap, tagStatsMap);
}

}  // namespace bpf
}  // namespace android
