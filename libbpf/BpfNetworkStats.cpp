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

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "BpfNetworkStats"

namespace android {
namespace bpf {


// The limit for stats received by a unknown interface;
static const int64_t MAX_UNKNOWN_IFACE_BYTES = 100*1000;

static constexpr uint32_t BPF_OPEN_FLAGS = BPF_F_RDONLY;

int bpfGetUidStatsInternal(uid_t uid, Stats* stats, const base::unique_fd& map_fd) {
    struct StatsValue dummyValue;
    auto processUidStats = [uid, stats](void *key, const base::unique_fd& map_fd) {
        if (((StatsKey *) key)->uid != uid) {
            return BPF_CONTINUE;
        }
        StatsValue statsEntry;
        int ret = bpf::findMapEntry(map_fd, key, &statsEntry);
        if (ret) return -errno;
        stats->rxPackets += statsEntry.rxPackets;
        stats->txPackets += statsEntry.txPackets;
        stats->rxBytes += statsEntry.rxBytes;
        stats->txBytes += statsEntry.txBytes;
        return BPF_CONTINUE;
    };
    return bpfIterateMap(dummyValue, map_fd, processUidStats);
}

int bpfGetUidStats(uid_t uid, Stats* stats) {
    base::unique_fd uidStatsMap(bpf::mapRetrieve(UID_STATS_MAP_PATH, BPF_OPEN_FLAGS));
    if (uidStatsMap < 0) {
        int ret = -errno;
        ALOGE("Opening map fd from %s failed: %s", UID_STATS_MAP_PATH, strerror(errno));
        return ret;
    }
    return bpfGetUidStatsInternal(uid, stats, uidStatsMap);
}

int bpfGetIfaceStatsInternal(const char* iface, Stats* stats,
                             const base::unique_fd& ifaceStatsMapFd,
                             const base::unique_fd& ifaceNameMapFd) {
    uint32_t dummyKey;
    int64_t unknownIfaceBytesTotal = 0;
    stats->tcpRxPackets = -1;
    stats->tcpTxPackets = -1;
    auto processIfaceStats = [iface, stats, &ifaceNameMapFd, &unknownIfaceBytesTotal](
                              void* key, const base::unique_fd& ifaceStatsMapFd) {
        char ifname[IFNAMSIZ];
        int ifIndex = *(int *)key;
        if (getIfaceNameFromMap(ifaceNameMapFd, ifaceStatsMapFd, ifIndex, ifname, &ifIndex,
                                &unknownIfaceBytesTotal)) {
            return BPF_CONTINUE;
        }
        if (!iface || !strcmp(iface, ifname)) {
            StatsValue statsEntry;
            int ret = bpf::findMapEntry(ifaceStatsMapFd, &ifIndex, &statsEntry);
            if (ret) return -errno;
            stats->rxPackets += statsEntry.rxPackets;
            stats->txPackets += statsEntry.txPackets;
            stats->rxBytes += statsEntry.rxBytes;
            stats->txBytes += statsEntry.txBytes;
        }
        return BPF_CONTINUE;
    };
    return bpfIterateMap(dummyKey, ifaceStatsMapFd, processIfaceStats);
}

int bpfGetIfaceStats(const char* iface, Stats* stats) {
    base::unique_fd ifaceStatsMap(bpf::mapRetrieve(IFACE_STATS_MAP_PATH, BPF_OPEN_FLAGS));
    int ret;
    if (ifaceStatsMap < 0) {
        ret = -errno;
        ALOGE("get ifaceStats map fd failed: %s", strerror(errno));
        return ret;
    }
    base::unique_fd ifaceIndexNameMap(bpf::mapRetrieve(IFACE_INDEX_NAME_MAP_PATH, BPF_OPEN_FLAGS));
    if (ifaceIndexNameMap < 0) {
        ret = -errno;
        ALOGE("get ifaceIndexName map fd failed: %s", strerror(errno));
        return ret;
    }
    return bpfGetIfaceStatsInternal(iface, stats, ifaceStatsMap, ifaceIndexNameMap);
}

stats_line populateStatsEntry(const StatsKey& statsKey, const StatsValue& statsEntry,
                              const char* ifname) {
    stats_line newLine;
    strlcpy(newLine.iface, ifname, sizeof(newLine.iface));
    newLine.uid = (int32_t)statsKey.uid;
    newLine.set = (int32_t)statsKey.counterSet;
    newLine.tag = (int32_t)statsKey.tag;
    newLine.rxPackets = statsEntry.rxPackets;
    newLine.txPackets = statsEntry.txPackets;
    newLine.rxBytes = statsEntry.rxBytes;
    newLine.txBytes = statsEntry.txBytes;
    return newLine;
}

void maybeLogUnknownIface(int ifaceIndex, const base::unique_fd& statsMapFd, void* curKey,
                          int64_t* unknownIfaceBytesTotal) {
    // Have we already logged an error?
    if (*unknownIfaceBytesTotal == -1) {
        return;
    }

    // Are we undercounting enough data to be worth logging?
    StatsValue statsEntry;
    if (bpf::findMapEntry(statsMapFd, curKey, &statsEntry) < 0) {
        // No data is being undercounted.
        return;
    }

    *unknownIfaceBytesTotal += (statsEntry.rxBytes + statsEntry.txBytes);
    if (*unknownIfaceBytesTotal >= MAX_UNKNOWN_IFACE_BYTES) {
            ALOGE("Unknown name for ifindex %d with more than %" PRId64 " bytes of traffic",
                  ifaceIndex, *unknownIfaceBytesTotal);
            *unknownIfaceBytesTotal = -1;
    }
}

int getIfaceNameFromMap(const base::unique_fd& ifaceMapFd, const base::unique_fd& statsMapFd,
                        uint32_t ifaceIndex, char* ifname, void* curKey,
                        int64_t* unknownIfaceBytesTotal) {
    if (bpf::findMapEntry(ifaceMapFd, &ifaceIndex, ifname) < 0) {
        maybeLogUnknownIface(ifaceIndex, statsMapFd, curKey, unknownIfaceBytesTotal);
        return -ENODEV;
    }
    return 0;
}

int parseBpfNetworkStatsDetailInternal(std::vector<stats_line>* lines,
                                       const std::vector<std::string>& limitIfaces, int limitTag,
                                       int limitUid, const base::unique_fd& statsMapFd,
                                       const base::unique_fd& ifaceMapFd) {
    int64_t unknownIfaceBytesTotal = 0;
    struct StatsKey dummyKey;
    auto processDetailUidStats = [lines, &limitIfaces, limitTag, limitUid,
                                  &unknownIfaceBytesTotal, &ifaceMapFd]
                                  (void* key, const base::unique_fd& statsMapFd) {
        struct StatsKey curKey = * (struct StatsKey*)key;
        char ifname[IFNAMSIZ];
        if (getIfaceNameFromMap(ifaceMapFd, statsMapFd, curKey.ifaceIndex, ifname, &curKey,
                                &unknownIfaceBytesTotal)) {
            return BPF_CONTINUE;
        }
        std::string ifnameStr(ifname);
        if (limitIfaces.size() > 0 &&
            std::find(limitIfaces.begin(), limitIfaces.end(), ifnameStr) == limitIfaces.end()) {
            // Nothing matched; skip this line.
            return BPF_CONTINUE;
        }
        if (limitTag != TAG_ALL && uint32_t(limitTag) != curKey.tag) {
            return BPF_CONTINUE;
        }
        if (limitUid != UID_ALL && uint32_t(limitUid) != curKey.uid) {
            return BPF_CONTINUE;
        }
        StatsValue statsEntry;
        if (bpf::findMapEntry(statsMapFd, &curKey, &statsEntry) < 0) return -errno;
        lines->push_back(populateStatsEntry(curKey, statsEntry, ifname));
        return BPF_CONTINUE;
    };
    return bpfIterateMap(dummyKey, statsMapFd, processDetailUidStats);
}

int parseBpfNetworkStatsDetail(std::vector<stats_line>* lines,
                               const std::vector<std::string>& limitIfaces, int limitTag,
                               int limitUid) {
    int ret = 0;
    base::unique_fd ifaceIndexNameMap(bpf::mapRetrieve(IFACE_INDEX_NAME_MAP_PATH, BPF_OPEN_FLAGS));
    if (ifaceIndexNameMap < 0) {
        ret = -errno;
        ALOGE("get ifaceIndexName map fd failed: %s", strerror(errno));
        return ret;
    }

    // If the caller did not pass in TAG_NONE, read tag data.
    if (limitTag != TAG_NONE) {
        base::unique_fd tagStatsMap(bpf::mapRetrieve(TAG_STATS_MAP_PATH, BPF_OPEN_FLAGS));
        if (tagStatsMap < 0) {
            ret = -errno;
            ALOGE("get tagStats map fd failed: %s", strerror(errno));
            return ret;
        }
        ret = parseBpfNetworkStatsDetailInternal(lines, limitIfaces, limitTag, limitUid,
                                                 tagStatsMap, ifaceIndexNameMap);
        if (ret) return ret;
    }

    // If the caller did not pass in a specific tag (i.e., if limitTag is TAG_NONE(0) or
    // TAG_ALL(-1)) read UID data.
    if (limitTag == TAG_NONE || limitTag == TAG_ALL) {
        base::unique_fd uidStatsMap(bpf::mapRetrieve(UID_STATS_MAP_PATH, BPF_OPEN_FLAGS));
        if (uidStatsMap < 0) {
            ret = -errno;
            ALOGE("Opening map fd from %s failed: %s", UID_STATS_MAP_PATH, strerror(errno));
            return ret;
        }
        ret = parseBpfNetworkStatsDetailInternal(lines, limitIfaces, limitTag, limitUid,
                                                 uidStatsMap, ifaceIndexNameMap);
    }
    return ret;
}

int parseBpfNetworkStatsDevInternal(std::vector<stats_line>* lines,
                                    const base::unique_fd& statsMapFd,
                                    const base::unique_fd& ifaceMapFd) {
    int64_t unknownIfaceBytesTotal = 0;
    uint32_t dummyKey;
    struct StatsValue dummyValue;
    auto processDetailIfaceStats = [lines, &unknownIfaceBytesTotal, &ifaceMapFd](
                                    void* key, void* value, const base::unique_fd& statsMapFd) {
        uint32_t ifIndex = *(uint32_t*)key;
        char ifname[IFNAMSIZ];
        if (getIfaceNameFromMap(ifaceMapFd, statsMapFd, ifIndex, ifname, &ifIndex,
                                &unknownIfaceBytesTotal)) {
            return BPF_CONTINUE;
        }
        StatsValue* statsEntry = (StatsValue*)value;
        StatsKey fakeKey = {
            .uid = (uint32_t)UID_ALL, .counterSet = (uint32_t)SET_ALL, .tag = (uint32_t)TAG_NONE};
        lines->push_back(populateStatsEntry(fakeKey, *statsEntry, ifname));
        return BPF_CONTINUE;
    };
    return bpfIterateMapWithValue(dummyKey, dummyValue, statsMapFd, processDetailIfaceStats);
}

int parseBpfNetworkStatsDev(std::vector<stats_line>* lines) {
    int ret = 0;
    base::unique_fd ifaceIndexNameMap(bpf::mapRetrieve(IFACE_INDEX_NAME_MAP_PATH, BPF_OPEN_FLAGS));
    if (ifaceIndexNameMap < 0) {
        ret = -errno;
        ALOGE("get ifaceIndexName map fd failed: %s", strerror(errno));
        return ret;
    }

    base::unique_fd ifaceStatsMap(bpf::mapRetrieve(IFACE_STATS_MAP_PATH, BPF_OPEN_FLAGS));
    if (ifaceStatsMap < 0) {
        ret = -errno;
        ALOGE("get ifaceStats map fd failed: %s", strerror(errno));
        return ret;
    }
    return parseBpfNetworkStatsDevInternal(lines, ifaceStatsMap, ifaceIndexNameMap);
}

uint64_t combineUidTag(const uid_t uid, const uint32_t tag) {
    return (uint64_t)uid << 32 | tag;
}

}  // namespace bpf
}  // namespace android
