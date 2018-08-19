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

#ifndef LOG_TAG
#define LOG_TAG "bpfloader"
#endif

#include <arpa/inet.h>
#include <elf.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <log/log.h>

#include <netdutils/Misc.h>
#include <netdutils/Slice.h>
#include "bpf/BpfUtils.h"
#include "bpf/bpf_shared.h"

using android::base::unique_fd;
using android::netdutils::Slice;

#define BPF_PROG_PATH "/system/etc/bpf"
#define BPF_PROG_SRC BPF_PROG_PATH "/bpf_kern.o"

#define CLEANANDEXIT(ret, mapPatterns)                 \
    do {                                               \
        for (int i = 0; i < mapPatterns.size(); i++) { \
            if (mapPatterns[i].fd > -1) {              \
                close(mapPatterns[i].fd);              \
            }                                          \
        }                                              \
        return ret;                                    \
    } while (0)

using android::bpf::APP_UID_STATS_MAP_PATH;
using android::bpf::BPF_EGRESS_PROG_PATH;
using android::bpf::BPF_INGRESS_PROG_PATH;
using android::bpf::CGROUP_ROOT_PATH;
using android::bpf::CONFIGURATION_MAP_PATH;
using android::bpf::COOKIE_TAG_MAP_PATH;
using android::bpf::IFACE_STATS_MAP_PATH;
using android::bpf::TAG_STATS_MAP_PATH;
using android::bpf::UID_COUNTERSET_MAP_PATH;
using android::bpf::UID_OWNER_MAP_PATH;
using android::bpf::UID_STATS_MAP_PATH;
using android::bpf::XT_BPF_BLACKLIST_PROG_PATH;
using android::bpf::XT_BPF_EGRESS_PROG_PATH;
using android::bpf::XT_BPF_INGRESS_PROG_PATH;
using android::bpf::XT_BPF_WHITELIST_PROG_PATH;

using android::bpf::BpfMapInfo;
using android::bpf::BpfProgInfo;

int main() {
    const std::vector<BpfMapInfo> mapPatterns = {
            BpfMapInfo(COOKIE_TAG_MAP, COOKIE_TAG_MAP_PATH),
            BpfMapInfo(UID_COUNTERSET_MAP, UID_COUNTERSET_MAP_PATH),
            BpfMapInfo(APP_UID_STATS_MAP, APP_UID_STATS_MAP_PATH),
            BpfMapInfo(UID_STATS_MAP, UID_STATS_MAP_PATH),
            BpfMapInfo(TAG_STATS_MAP, TAG_STATS_MAP_PATH),
            BpfMapInfo(IFACE_STATS_MAP, IFACE_STATS_MAP_PATH),
            BpfMapInfo(CONFIGURATION_MAP, CONFIGURATION_MAP_PATH),
            BpfMapInfo(UID_OWNER_MAP, UID_OWNER_MAP_PATH),
    };
    for (int i = 0; i < mapPatterns.size(); i++) {
        if (mapPatterns[i].fd < 0) {
            ALOGE("Rerieve Map from %s failed: %d", mapPatterns[i].path.c_str(), mapPatterns[i].fd);
            CLEANANDEXIT(-1, mapPatterns);
        }
    }
    BpfProgInfo programs[] = {
            {BPF_CGROUP_INET_EGRESS, BPF_EGRESS_PROG_PATH, BPF_CGROUP_EGRESS_PROG_NAME,
             BPF_PROG_TYPE_CGROUP_SKB, unique_fd(-1)},
            {BPF_CGROUP_INET_INGRESS, BPF_INGRESS_PROG_PATH, BPF_CGROUP_INGRESS_PROG_NAME,
             BPF_PROG_TYPE_CGROUP_SKB, unique_fd(-1)},
            {MAX_BPF_ATTACH_TYPE, XT_BPF_INGRESS_PROG_PATH, XT_BPF_INGRESS_PROG_NAME,
             BPF_PROG_TYPE_SOCKET_FILTER, unique_fd(-1)},
            {MAX_BPF_ATTACH_TYPE, XT_BPF_EGRESS_PROG_PATH, XT_BPF_EGRESS_PROG_NAME,
             BPF_PROG_TYPE_SOCKET_FILTER, unique_fd(-1)},
            {MAX_BPF_ATTACH_TYPE, XT_BPF_WHITELIST_PROG_PATH, XT_BPF_WHITELIST_PROG_NAME,
             BPF_PROG_TYPE_SOCKET_FILTER, unique_fd(-1)},
            {MAX_BPF_ATTACH_TYPE, XT_BPF_BLACKLIST_PROG_PATH, XT_BPF_BLACKLIST_PROG_NAME,
             BPF_PROG_TYPE_SOCKET_FILTER, unique_fd(-1)}};
    int ret = android::bpf::parseProgramsFromFile(BPF_PROG_SRC, programs, ARRAY_SIZE(programs),
                                                  mapPatterns);
    CLEANANDEXIT(ret, mapPatterns);
}
