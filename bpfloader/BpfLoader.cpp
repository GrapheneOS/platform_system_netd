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

#include <error.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include <netdutils/Misc.h>
#include "BpfProgSets.h"
#include "bpf/BpfUtils.h"

using android::base::unique_fd;

namespace android {
namespace bpf {

int loadAndAttachProgram(bpf_attach_type type, const char* path, const char* name,
                         const unique_fd& cookieTagMap, const unique_fd& uidCounterSetMap,
                         const unique_fd& uidStatsMap, const unique_fd& tagStatsMap) {
    unique_fd cg_fd(open(CGROUP_ROOT_PATH, O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    if (cg_fd < 0) {
        perror("Failed to open the cgroup directory");
        return -1;
    }

    unique_fd fd;
    if (type == BPF_CGROUP_INET_EGRESS) {
        fd.reset(loadEgressProg(cookieTagMap.get(), uidStatsMap.get(), tagStatsMap.get(),
                                uidCounterSetMap.get()));
    } else {
        fd.reset(loadIngressProg(cookieTagMap.get(), uidStatsMap.get(), tagStatsMap.get(),
                                 uidCounterSetMap.get()));
    }

    if (fd < 0) {
        fprintf(stderr, "load %s failed: %s", name, strerror(errno));
        return -1;
    }

    int ret = attachProgram(type, fd, cg_fd);
    if (ret) {
        fprintf(stderr, "%s attach failed: %s", name, strerror(errno));
        return -1;
    }

    ret = mapPin(fd, path);
    if (ret) {
        fprintf(stderr, "Pin %s as file %s failed: %s", name, path, strerror(errno));
        return -1;
    }
    return 0;
}

}  // namespace bpf
}  // namespace android

using android::bpf::BPF_EGRESS_PROG_PATH;
using android::bpf::BPF_INGRESS_PROG_PATH;
using android::bpf::COOKIE_UID_MAP_PATH;
using android::bpf::TAG_STATS_MAP_PATH;
using android::bpf::UID_COUNTERSET_MAP_PATH;
using android::bpf::UID_STATS_MAP_PATH;

static void usage(void) {
    fprintf(stderr,
            "Usage: ./bpfloader [-i] [-e]\n"
            "   -i load ingress bpf program\n"
            "   -e load egress bpf program\n");
}

int main(int argc, char** argv) {
    int ret = 0;
    unique_fd cookieTagMap(android::bpf::mapRetrieve(COOKIE_UID_MAP_PATH, 0));
    if (cookieTagMap < 0) {
        perror("Failed to get cookieTagMap");
        exit(-1);
    }

    unique_fd uidCounterSetMap(android::bpf::mapRetrieve(UID_COUNTERSET_MAP_PATH, 0));
    if (uidCounterSetMap < 0) {
        perror("Failed to get uidCounterSetMap");
        exit(-1);
    }

    unique_fd uidStatsMap(android::bpf::mapRetrieve(UID_STATS_MAP_PATH, 0));
    if (uidStatsMap < 0) {
        perror("Failed to get uidStatsMap");
        exit(-1);
    }

    unique_fd tagStatsMap(android::bpf::mapRetrieve(TAG_STATS_MAP_PATH, 0));
    if (tagStatsMap < 0) {
        perror("Failed to get tagStatsMap");
        exit(-1);
    }
    int opt;
    bool doIngress = false, doEgress = false;
    while ((opt = getopt(argc, argv, "ie")) != -1) {
        switch (opt) {
            case 'i':
                doIngress = true;
                break;
            case 'e':
                doEgress = true;
                break;
            default:
                fprintf(stderr, "unknown argument %c", opt);
                usage();
                exit(-1);
        }
    }
    if (doIngress) {
        ret = android::bpf::loadAndAttachProgram(BPF_CGROUP_INET_INGRESS, BPF_INGRESS_PROG_PATH,
                                                 "ingress_prog", cookieTagMap, uidCounterSetMap,
                                                 uidStatsMap, tagStatsMap);
        if (ret) {
            fprintf(stderr, "Failed to set up ingress program");
            return ret;
        }
    }
    if (doEgress) {
        ret = android::bpf::loadAndAttachProgram(BPF_CGROUP_INET_EGRESS, BPF_EGRESS_PROG_PATH,
                                                 "egress_prog", cookieTagMap, uidCounterSetMap,
                                                 uidStatsMap, tagStatsMap);
        if (ret) {
            fprintf(stderr, "Failed to set up ingress program");
            return ret;
        }
    }
    return ret;
}
