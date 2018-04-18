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

namespace android {
namespace bpf {

// TODO: set this to a proper value based on the map size;
constexpr int TAG_STATS_MAP_SOFT_LIMIT = 3;
constexpr int UID_ALL = -1;
constexpr int TAG_ALL = -1;
constexpr int TAG_NONE = 0;
constexpr int SET_ALL = -1;
constexpr int SET_DEFAULT = 0;
constexpr int SET_FOREGROUND = 1;

struct stats_line {
    char iface[32];
    int32_t uid;
    int32_t set;
    int32_t tag;
    int64_t rxBytes;
    int64_t rxPackets;
    int64_t txBytes;
    int64_t txPackets;
};
// For test only
int bpfGetUidStatsInternal(uid_t uid, struct Stats* stats, const base::unique_fd& map_fd);
// For test only
int bpfGetIfaceStatsInternal(const char* iface, Stats* stats,
                             const base::unique_fd& ifaceStatsMapFd,
                             const base::unique_fd& ifaceNameMapFd);
// For test only
int parseBpfNetworkStatsDetailInternal(std::vector<stats_line>* lines,
                                       const std::vector<std::string>& limitIfaces, int limitTag,
                                       int limitUid, const base::unique_fd& statsMapFd,
                                       const base::unique_fd& ifaceMapFd);
// For test only
int cleanStatsMapInternal(const base::unique_fd& cookieTagMap, const base::unique_fd& tagStatsMap);
// For test only
int getIfaceNameFromMap(const base::unique_fd& ifaceMapFd, const base::unique_fd& statsMapFd,
                        uint32_t ifaceIndex, char* ifname, void* curKey,
                        int64_t* unknownIfaceBytesTotal);
// For test only
int parseBpfNetworkStatsDevInternal(std::vector<stats_line>* lines,
                                    const base::unique_fd& statsMapFd,
                                    const base::unique_fd& ifaceMapFd);

int bpfGetUidStats(uid_t uid, struct Stats* stats);
int bpfGetIfaceStats(const char* iface, struct Stats* stats);
int parseBpfNetworkStatsDetail(std::vector<stats_line>* lines,
                               const std::vector<std::string>& limitIfaces, int limitTag,
                               int limitUid);

int parseBpfNetworkStatsDev(std::vector<stats_line>* lines);
int cleanStatsMap();
}  // namespace bpf
}  // namespace android
