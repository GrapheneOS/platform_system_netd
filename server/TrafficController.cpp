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
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/inet_diag.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#include "BpfProgSets.h"
#include "BpfUtils.h"
#include "TrafficController.h"

#define LOG_TAG "Netd"
#include "log/log.h"
#include "qtaguid/qtaguid.h"

using namespace android::net::bpf;
using namespace android::net::bpf_prog;

namespace android {
namespace net {

int TrafficController::start() {
    int ret;
    struct utsname buf;
    int kernel_version_major;
    int kernel_version_minor;

    ret = uname(&buf);
    if (ret) {
        ret = -errno;
        ALOGE("Get system information failed: %s\n", strerror(errno));
        return ret;
    }
    ret = sscanf(buf.release, "%d.%d", &kernel_version_major, &kernel_version_minor);
    if (ret >= 2 && ((kernel_version_major == 4 && kernel_version_minor >= 9) ||
                     (kernel_version_major > 4))) {
        // Turn off the eBPF feature temporarily since the selinux rules and kernel changes are not
        // landed yet.
        // TODO: turn back on when all the other dependencies are ready.
        ebpfSupported = false;
        return 0;
    } else {
        ebpfSupported = false;
        return 0;
    }
    ALOGI("START to load TrafficController\n");
    mCookieTagMap = setUpBPFMap(sizeof(uint64_t), sizeof(struct UidTag), COOKIE_UID_MAP_SIZE,
                                COOKIE_UID_MAP_PATH, BPF_MAP_TYPE_HASH);
    if (mCookieTagMap < 0) {
        ret = -errno;
        ALOGE("mCookieTagMap load failed\n");
        return ret;
    }
    mUidCounterSetMap = setUpBPFMap(sizeof(uint32_t), sizeof(uint32_t), UID_COUNTERSET_MAP_SIZE,
                                    UID_COUNTERSET_MAP_PATH, BPF_MAP_TYPE_HASH);
    if (mUidCounterSetMap < 0) {
        ret = -errno;
        ALOGE("mUidCounterSetMap load failed\n");
        return ret;
    }
    mUidStatsMap = setUpBPFMap(sizeof(struct StatsKey), sizeof(struct Stats), UID_STATS_MAP_SIZE,
                               UID_STATS_MAP_PATH, BPF_MAP_TYPE_HASH);
    if (mUidStatsMap < 0) {
        ret = -errno;
        ALOGE("mUidStatsMap load failed\n");
        return ret;
    }
    mTagStatsMap = setUpBPFMap(sizeof(struct StatsKey), sizeof(struct Stats), TAG_STATS_MAP_SIZE,
                               TAG_STATS_MAP_PATH, BPF_MAP_TYPE_HASH);
    if (mTagStatsMap < 0) {
        ret = -errno;
        ALOGE("mTagStatsMap load failed\n");
        return ret;
    }

    /* When netd restart from a crash without total system reboot, the program
     * is still attached to the cgroup, detach it so the program can be freed
     * and we can load and attach new program into the target cgroup.
     *
     * TODO: Scrape existing socket when run-time restart and clean up the map
     * if the socket no longer exist
     */

    int cg_fd = open(CGROUP_ROOT_PATH, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (cg_fd < 0) {
        ret = -errno;
        ALOGE("Failed to open the cgroup directory\n");
        return ret;
    }

    ret = detachProgram(BPF_CGROUP_INET_EGRESS, cg_fd);
    ret = detachProgram(BPF_CGROUP_INET_INGRESS, cg_fd);

    mInProgFd = loadIngressProg(mCookieTagMap, mUidStatsMap, mTagStatsMap, mUidCounterSetMap);
    if (mInProgFd < 0) {
        ret = -errno;
        ALOGE("Load ingress program failed\n");
        return ret;
    }

    mOutProgFd = loadEgressProg(mCookieTagMap, mUidStatsMap, mTagStatsMap, mUidCounterSetMap);
    if (mOutProgFd < 0) {
        ret = -errno;
        ALOGE("load egress program failed\n");
        return ret;
    }

    ret = attachProgram(BPF_CGROUP_INET_EGRESS, mOutProgFd, cg_fd);
    if (ret) {
        ret = -errno;
        ALOGE("egress program attach failed: %s\n", strerror(errno));
        return ret;
    }

    ret = attachProgram(BPF_CGROUP_INET_INGRESS, mInProgFd, cg_fd);
    if (ret) {
        ret = -errno;
        ALOGE("ingress program attach failed: %s\n", strerror(errno));
        return ret;
    }
    close(cg_fd);
    return 0;
}

uint64_t getSocketCookie(int sockFd) {
    uint64_t sock_cookie;
    socklen_t cookie_len = sizeof(sock_cookie);
    int res = getsockopt(sockFd, SOL_SOCKET, SO_COOKIE, &sock_cookie, &cookie_len);
    if (res < 0) {
        res = -errno;
        ALOGE("Failed to get socket cookie: %s\n", strerror(errno));
        errno = -res;
        // 0 is an invalid cookie. See INET_DIAG_NOCOOKIE.
        return 0;
    }
    return sock_cookie;
}

int TrafficController::tagSocket(int sockFd, uint32_t tag, uid_t uid) {

    if (legacy_tagSocket(sockFd, tag, uid))
      return -errno;
    if (!ebpfSupported)
      return 0;

    uint64_t sock_cookie = getSocketCookie(sockFd);
    if (sock_cookie == INET_DIAG_NOCOOKIE) return -errno;
    UidTag newKey = {.uid = (uint32_t)uid, .tag = tag};

    // Update the tag information of a socket to the cookieUidMap. Use BPF_ANY
    // flag so it will insert a new entry to the map if that value doesn't exist
    // yet. And update the tag if there is already a tag stored. Since the eBPF
    // program in kernel only read this map, and is protected by rcu read lock. It
    // should be fine to cocurrently update the map while eBPF program is running.
    int res = writeToMapEntry(mCookieTagMap, &sock_cookie, &newKey, BPF_ANY);
    if (res < 0) {
        res = -errno;
        ALOGE("Failed to tag the socket: %s\n", strerror(errno));
    }

    return res;
}

int TrafficController::untagSocket(int sockFd) {

    if (legacy_untagSocket(sockFd))
        return -errno;
    if (!ebpfSupported) return 0;
    uint64_t sock_cookie = getSocketCookie(sockFd);

    if (sock_cookie == INET_DIAG_NOCOOKIE) return -errno;
    int res = deleteMapEntry(mCookieTagMap, &sock_cookie);
    if (res) {
        res = -errno;
        ALOGE("Failed to untag socket: %s\n", strerror(errno));
    }
    return res;
}

int TrafficController::setCounterSet(int counterSetNum, uid_t uid) {
    if (counterSetNum < 0 || counterSetNum >= COUNTERSETS_LIMIT) return -EINVAL;
    int res;
    if (legacy_setCounterSet(counterSetNum, uid))
        return -errno;
    if (!ebpfSupported) return 0;;
    if (counterSetNum == 0) {
        res = deleteMapEntry(mUidCounterSetMap, &uid);
        if (res == 0 || (res == -1 && errno == ENOENT)) {
            return 0;
        } else {
            ALOGE("Failed to delete the counterSet: %s\n", strerror(errno));
            return -errno;
        }
    }

    res = writeToMapEntry(mUidCounterSetMap, &uid, &counterSetNum, BPF_ANY);
    if (res < 0) {
        res = -errno;
        ALOGE("Failed to set the counterSet: %s\n", strerror(errno));
    }
    return res;
}

int TrafficController::deleteTagData(uint32_t tag, uid_t uid) {
    int res = 0;

    if (legacy_deleteTagData(tag, uid))
        return -errno;
    if (!ebpfSupported) return 0;

    uint64_t curCookie = 0;
    uint64_t nextCookie = 0;
    UidTag tmp_uidtag;
    bool end = false;

    // First we go through the cookieTagMap to delete the target uid tag combanition. Or delete all
    // the tags related to the uid if the tag is 0
    while (!end && getNextMapKey(mCookieTagMap, &curCookie, &nextCookie) > -1) {
        curCookie = nextCookie;
        res = findMapEntry(mCookieTagMap, &curCookie, &tmp_uidtag);
        if (res < 0) {
            res = -errno;
            ALOGE("Failed to get tag info(cookie = %" PRIu64": %s\n", curCookie, strerror(errno));
            return res;
        }

        if (tmp_uidtag.uid == uid && (tmp_uidtag.tag == tag || tag == 0)) {
            // To prevent we iterrate the map again from the begining, we firstly get the key next
            // to the key we are going to delete here. And use it as the key when we get next entry.
            res = getNextMapKey(mCookieTagMap, &curCookie, &nextCookie);
            if (res == -1) end = true;
            res = deleteMapEntry(mCookieTagMap, &curCookie);
            if (res != 0 || (res == -1 && errno != ENOENT)) {
                res = -errno;
                ALOGE("Failed to delete data(uid=%u, tag=%u): %s\n", uid, tag, strerror(errno));
                return res;
            }
            curCookie = nextCookie;
        }
    }

    // Now we go through the Tag stats map and delete the data entry with correct uid and tag
    // combanition. Or all tag stats under that uid if the target tag is 0.
    struct StatsKey curKey, nextKey;
    memset(&curKey, 0, sizeof(curKey));
    curKey.uid = DEFAULT_OVERFLOWUID;
    end = false;
    while (getNextMapKey(mTagStatsMap, &curKey, &nextKey) > -1) {
        curKey = nextKey;
        if (curKey.uid == uid && (curKey.tag == tag || tag == 0)) {
            res = getNextMapKey(mTagStatsMap, &curKey, &nextKey);
            if (res == -1) end = true;
            res = deleteMapEntry(mTagStatsMap, &curKey);
            if (res != 0 || (res == -1 && errno != ENOENT)) {
                res = -errno;
                ALOGE("Failed to delete data(uid=%u, tag=%u): %s\n", uid, tag, strerror(errno));
                return res;
            }
            curKey = nextKey;
        }
    }

    // If the tag is not zero, we already deleted all the data entry required. If tag is 0, we also
    // need to delete the stats stored in uidStatsMap
    if (tag != 0) return res;
    memset(&curKey, 0, sizeof(curKey));
    curKey.uid = DEFAULT_OVERFLOWUID;
    end = false;
    while (getNextMapKey(mUidStatsMap, &curKey, &nextKey) > -1) {
        curKey = nextKey;
        if (curKey.uid == uid) {
            res = getNextMapKey(mTagStatsMap, &curKey, &nextKey);
            if (res == -1) end = true;
            res = deleteMapEntry(mUidStatsMap, &curKey);
            if (res != 0 || (res == -1 && errno != ENOENT)) {
                res = -errno;
                ALOGE("Failed to delete data(uid=%u, tag=%u): %s\n", uid, tag, strerror(errno));
                return res;
            }
            curKey = nextKey;
        }
    }
    return res;
}

}  // namespace net
}  // namespace android
