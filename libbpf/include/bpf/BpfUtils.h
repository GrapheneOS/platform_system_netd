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

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "android-base/unique_fd.h"
#include "netdutils/Slice.h"
#include "netdutils/StatusOr.h"

#define ptr_to_u64(x) ((uint64_t)(uintptr_t)x)
#define DEFAULT_LOG_LEVEL 1

#define BPF_PASS 1
#define BPF_DROP 0

namespace android {
namespace bpf {

struct UidTag {
    uint32_t uid;
    uint32_t tag;
};

struct StatsKey {
    uint32_t uid;
    uint32_t tag;
    uint32_t counterSet;
    uint32_t ifaceIndex;
};

struct StatsValue {
    uint64_t rxPackets;
    uint64_t rxBytes;
    uint64_t txPackets;
    uint64_t txBytes;
};

struct Stats {
    uint64_t rxBytes;
    uint64_t rxPackets;
    uint64_t txBytes;
    uint64_t txPackets;
    uint64_t tcpRxPackets;
    uint64_t tcpTxPackets;
};

#ifndef DEFAULT_OVERFLOWUID
#define DEFAULT_OVERFLOWUID 65534
#endif

#define BPF_PATH "/sys/fs/bpf"

constexpr const char* BPF_EGRESS_PROG_PATH = BPF_PATH "/egress_prog";
constexpr const char* BPF_INGRESS_PROG_PATH = BPF_PATH "/ingress_prog";
constexpr const char* XT_BPF_INGRESS_PROG_PATH = BPF_PATH "/xt_bpf_ingress_prog";
constexpr const char* XT_BPF_EGRESS_PROG_PATH = BPF_PATH "/xt_bpf_egress_prog";

constexpr const char* CGROUP_ROOT_PATH = "/dev/cg2_bpf";

constexpr const char* COOKIE_TAG_MAP_PATH = BPF_PATH "/traffic_cookie_tag_map";
constexpr const char* UID_COUNTERSET_MAP_PATH = BPF_PATH "/traffic_uid_counterSet_map";
constexpr const char* UID_STATS_MAP_PATH = BPF_PATH "/traffic_uid_stats_map";
constexpr const char* TAG_STATS_MAP_PATH = BPF_PATH "/traffic_tag_stats_map";
constexpr const char* IFACE_INDEX_NAME_MAP_PATH = BPF_PATH "/traffic_iface_index_name_map";
constexpr const char* IFACE_STATS_MAP_PATH = BPF_PATH "/traffic_iface_stats_map";
constexpr const char* DOZABLE_UID_MAP_PATH = BPF_PATH "/traffic_dozable_uid_map";
constexpr const char* STANDBY_UID_MAP_PATH = BPF_PATH "/traffic_standby_uid_map";
constexpr const char* POWERSAVE_UID_MAP_PATH = BPF_PATH "/traffic_powersave_uid_map";

const StatsKey NONEXISTENT_STATSKEY = {
    .uid = DEFAULT_OVERFLOWUID,
};

const uint32_t NONEXISTENT_UID = DEFAULT_OVERFLOWUID;
const uint32_t NONEXISTENT_IFACE_STATS_KEY = 0;

int createMap(bpf_map_type map_type, uint32_t key_size, uint32_t value_size,
              uint32_t max_entries, uint32_t map_flags);
int writeToMapEntry(const base::unique_fd& map_fd, void* key, void* value, uint64_t flags);
int findMapEntry(const base::unique_fd& map_fd, void* key, void* value);
int deleteMapEntry(const base::unique_fd& map_fd, void* key);
int getNextMapKey(const base::unique_fd& map_fd, void* key, void* next_key);
int bpfProgLoad(bpf_prog_type prog_type, netdutils::Slice bpf_insns, const char* license,
                uint32_t kern_version, netdutils::Slice bpf_log);
int mapPin(const base::unique_fd& map_fd, const char* pathname);
int mapRetrieve(const char* pathname, uint32_t flags);
int attachProgram(bpf_attach_type type, uint32_t prog_fd, uint32_t cg_fd);
int detachProgram(bpf_attach_type type, uint32_t cg_fd);
uint64_t getSocketCookie(int sockFd);
netdutils::StatusOr<base::unique_fd> setUpBPFMap(uint32_t key_size, uint32_t value_size,
                                                 uint32_t map_size, const char* path,
                                                 bpf_map_type map_type);
bool hasBpfSupport();

typedef std::function<int(void* key, const base::unique_fd& map_fd)> BpfMapEntryFilter;
template <class Key, class Value>
int bpfIterateMap(const Key& nonExistentKey, const Value& /* dummy */,
                  const base::unique_fd& map_fd, const BpfMapEntryFilter& filter) {
    Key curKey = nonExistentKey;
    Key nextKey;
    int ret = 0;
    Value dummyEntry;
    if (bpf::findMapEntry(map_fd, &curKey, &dummyEntry) == 0) {
        ALOGE("This entry should never exist in map!");
        return -EUCLEAN;
    }
    while (bpf::getNextMapKey(map_fd, &curKey, &nextKey) != -1) {
        curKey = nextKey;
        if ((ret = filter(&curKey, map_fd))) return ret;
    }
    // Return errno if getNextMapKey return error before hit to the end of the map.
    if (errno != ENOENT) {
        ret = errno;
        ALOGE("bpfIterateMap failed on MAP_FD: %d, error: %s", map_fd.get(), strerror(errno));
        return -ret;
    }
    return 0;
}

typedef std::function<int(void* key, void* value)> BpfMapEntryFilterWithValue;
template <class Key, class Value>
int bpfIterateMapWithValue(const Key& nonExistentKey, const Value& /* dummy */,
                           const base::unique_fd& map_fd,
                           const BpfMapEntryFilterWithValue& filter) {
    Key curKey = nonExistentKey;
    Key nextKey;
    int ret = 0;
    Value curValue;
    if (bpf::findMapEntry(map_fd, &curKey, &curValue) == 0) {
        ALOGE("This entry should never exist in map!");
        return -EUCLEAN;
    }
    while (bpf::getNextMapKey(map_fd, &curKey, &nextKey) != -1) {
        curKey = nextKey;
        ret = bpf::findMapEntry(map_fd, &curKey, &curValue);
        if (ret) {
            ALOGE("Get current value failed");
            return ret;
        }
        if ((ret = filter(&curKey, &curValue))) return ret;
    }
    // Return errno if getNextMapKey return error before hit to the end of the map.
    if (errno != ENOENT) {
        ret = errno;
        ALOGE("bpfIterateMap failed on MAP_FD: %d, error: %s", map_fd.get(), strerror(errno));
        return -ret;
    }
    return 0;
}
}  // namespace bpf
}  // namespace android
