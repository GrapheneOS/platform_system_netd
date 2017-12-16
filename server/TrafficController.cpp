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

#define LOG_TAG "TrafficController"

#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/unistd.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unordered_set>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <netdutils/StatusOr.h>

#include <netdutils/Misc.h>
#include <netdutils/Syscalls.h>
#include "BpfProgSets.h"
#include "TrafficController.h"
#include "bpf/BpfUtils.h"

#include "NetlinkListener.h"
#include "qtaguid/qtaguid.h"

using namespace android::bpf;
using namespace android::net::bpf_prog;

namespace android {
namespace net {

using base::StringPrintf;
using base::unique_fd;
using netdutils::extract;
using netdutils::Slice;
using netdutils::sSyscalls;
using netdutils::Status;
using netdutils::statusFromErrno;
using netdutils::StatusOr;
using netdutils::status::ok;

Status TrafficController::loadAndAttachProgram(bpf_attach_type type, const char* path,
                                               const char* name, base::unique_fd& cg_fd) {
    base::unique_fd fd;
    int ret = access(path, R_OK);
    if (ret == 0) {
        // The program already exist and we can access it.
        return netdutils::status::ok;
    }

    if (errno != ENOENT) {
        // The program exist but we cannot access it.
        return statusFromErrno(errno, StringPrintf("Cannot access %s at path: %s", name, path));
    }

    // Program does not exist yet. Load, attach and pin it.
    if (type == BPF_CGROUP_INET_EGRESS) {
        fd.reset(loadEgressProg(mCookieTagMap.get(), mUidStatsMap.get(), mTagStatsMap.get(),
                                mUidCounterSetMap.get()));
    } else {
        fd.reset(loadIngressProg(mCookieTagMap.get(), mUidStatsMap.get(), mTagStatsMap.get(),
                                 mUidCounterSetMap.get()));
    }
    if (fd < 0) {
        return statusFromErrno(errno, StringPrintf("load %s failed", name));
    }

    ret = attachProgram(type, fd, cg_fd);
    if (ret) {
        return statusFromErrno(errno, StringPrintf("%s attach failed", name));
    }

    ret = mapPin(fd, path);
    if (ret) {
        return statusFromErrno(errno, StringPrintf("Pin %s as file failed(%s)", name, path));
    }
    return netdutils::status::ok;
}

constexpr int kSockDiagMsgType = SOCK_DIAG_BY_FAMILY;
constexpr int kSockDiagDoneMsgType = NLMSG_DONE;

StatusOr<std::unique_ptr<NetlinkListenerInterface>> makeSkDestroyListener() {
    const auto& sys = sSyscalls.get();
    ASSIGN_OR_RETURN(auto event, sys.eventfd(0, EFD_CLOEXEC));
    const int domain = AF_NETLINK;
    const int type = SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
    const int protocol = NETLINK_INET_DIAG;
    ASSIGN_OR_RETURN(auto sock, sys.socket(domain, type, protocol));

    sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = 1 << (SKNLGRP_INET_TCP_DESTROY - 1) | 1 << (SKNLGRP_INET_UDP_DESTROY - 1) |
                     1 << (SKNLGRP_INET6_TCP_DESTROY - 1) | 1 << (SKNLGRP_INET6_UDP_DESTROY - 1)};
    RETURN_IF_NOT_OK(sys.bind(sock, addr));

    const sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    RETURN_IF_NOT_OK(sys.connect(sock, kernel));

    std::unique_ptr<NetlinkListenerInterface> listener =
        std::make_unique<NetlinkListener>(std::move(event), std::move(sock));

    return listener;
}

Status TrafficController::start() {
    ebpfSupported = hasBpfSupport();
    if (!ebpfSupported) {
        return netdutils::status::ok;
    }

    /* When netd restart from a crash without total system reboot, the program
     * is still attached to the cgroup, detach it so the program can be freed
     * and we can load and attach new program into the target cgroup.
     *
     * TODO: Scrape existing socket when run-time restart and clean up the map
     * if the socket no longer exist
     */

    ALOGI("START to load TrafficController");
    base::unique_fd cg_fd(open(CGROUP_ROOT_PATH, O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    if (cg_fd < 0) {
        return statusFromErrno(errno, "Failed to open the cgroup directory");
    }

    ASSIGN_OR_RETURN(mCookieTagMap,
                     setUpBPFMap(sizeof(uint64_t), sizeof(struct UidTag), COOKIE_UID_MAP_SIZE,
                                 COOKIE_UID_MAP_PATH, BPF_MAP_TYPE_HASH));

    // Allow both netd and system server to obtain map fd from the path. Chown the group to
    // net_bw_acct does not grant all process in that group the permission to access bpf maps. They
    // still need correct sepolicy to read/write the map. And only system_server and netd have that
    // permission for now.
    int ret = chown(COOKIE_UID_MAP_PATH, AID_ROOT, AID_NET_BW_ACCT);
    if (ret) {
        return statusFromErrno(errno, "change cookieTagMap group failed.");
    }
    ret = chmod(COOKIE_UID_MAP_PATH, S_IRWXU | S_IRGRP | S_IWGRP);
    if (ret) {
        return statusFromErrno(errno, "change cookieTagMap mode failed.");
    }

    ASSIGN_OR_RETURN(mUidCounterSetMap,
                     setUpBPFMap(sizeof(uint32_t), sizeof(uint32_t), UID_COUNTERSET_MAP_SIZE,
                                 UID_COUNTERSET_MAP_PATH, BPF_MAP_TYPE_HASH));
    // Only netd can access the file.
    ret = chmod(UID_COUNTERSET_MAP_PATH, S_IRWXU);
    if (ret) {
        return statusFromErrno(errno, "change uidCounterSetMap mode failed.");
    }

    ASSIGN_OR_RETURN(mUidStatsMap,
                     setUpBPFMap(sizeof(struct StatsKey), sizeof(struct StatsValue),
                                 UID_STATS_MAP_SIZE, UID_STATS_MAP_PATH, BPF_MAP_TYPE_HASH));
    // Change the file mode of pinned map so both netd and system server can get the map fd
    // from it.
    ret = chown(UID_STATS_MAP_PATH, AID_ROOT, AID_NET_BW_ACCT);
    if (ret) {
        return statusFromErrno(errno, "change uidStatsMap group failed.");
    }
    ret = chmod(UID_STATS_MAP_PATH, S_IRWXU | S_IRGRP | S_IWGRP);
    if (ret) {
        return statusFromErrno(errno, "change uidStatsMap mode failed.");
    }

    ASSIGN_OR_RETURN(mTagStatsMap,
                     setUpBPFMap(sizeof(struct StatsKey), sizeof(struct StatsValue),
                                 TAG_STATS_MAP_SIZE, TAG_STATS_MAP_PATH, BPF_MAP_TYPE_HASH));
    // Change the file mode of pinned map so both netd and system server can get the map fd
    // from the path.
    ret = chown(TAG_STATS_MAP_PATH, AID_ROOT, AID_NET_BW_STATS);
    if (ret) {
        return statusFromErrno(errno, "change tagStatsMap group failed.");
    }
    ret = chmod(TAG_STATS_MAP_PATH, S_IRWXU | S_IRGRP | S_IWGRP);
    if (ret) {
        return statusFromErrno(errno, "change tagStatsMap mode failed.");
    }

    auto result = makeSkDestroyListener();
    if (!isOk(result)) {
        ALOGE("Unable to create SkDestroyListener: %s", toString(result).c_str());
    } else {
        mSkDestroyListener = std::move(result.value());
    }
    // Rx handler extracts nfgenmsg looks up and invokes registered dispatch function.
    const auto rxHandler = [this](const nlmsghdr&, const Slice msg) {
        inet_diag_msg diagmsg = {};
        if (extract(msg, diagmsg) < sizeof(inet_diag_msg)) {
            ALOGE("unrecognized netlink message: %s", toString(msg).c_str());
            return;
        }
        uint64_t sock_cookie = static_cast<uint64_t>(diagmsg.id.idiag_cookie[0]) |
                               (static_cast<uint64_t>(diagmsg.id.idiag_cookie[1]) << 32);

        deleteMapEntry(mCookieTagMap, &sock_cookie);
    };
    expectOk(mSkDestroyListener->subscribe(kSockDiagMsgType, rxHandler));

    // In case multiple netlink message comes in as a stream, we need to handle the rxDone message
    // properly.
    const auto rxDoneHandler = [](const nlmsghdr&, const Slice msg) {
        // Ignore NLMSG_DONE  messages
        inet_diag_msg diagmsg = {};
        extract(msg, diagmsg);
    };
    expectOk(mSkDestroyListener->subscribe(kSockDiagDoneMsgType, rxDoneHandler));

    RETURN_IF_NOT_OK(loadAndAttachProgram(BPF_CGROUP_INET_INGRESS, BPF_INGRESS_PROG_PATH,
                                          "Ingress_prog", cg_fd));
    return loadAndAttachProgram(BPF_CGROUP_INET_EGRESS, BPF_EGRESS_PROG_PATH, "egress_prog", cg_fd);
}

int TrafficController::tagSocket(int sockFd, uint32_t tag, uid_t uid) {
    if (legacy_tagSocket(sockFd, tag, uid)) return -errno;
    if (!ebpfSupported) return 0;

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
        ALOGE("Failed to tag the socket: %s, fd: %d", strerror(errno), mCookieTagMap.get());
    }

    return res;
}

int TrafficController::untagSocket(int sockFd) {
    if (legacy_untagSocket(sockFd)) return -errno;
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
    if (legacy_setCounterSet(counterSetNum, uid)) return -errno;
    if (!ebpfSupported) return 0;

    // The default counter set for all uid is 0, so deleting the current counterset for that uid
    // will automatically set it to 0.
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
        ALOGE("Failed to set the counterSet: %s, fd: %d", strerror(errno), mUidCounterSetMap.get());
    }
    return res;
}

// TODO: Add a lock for delete tag Data so when several request for different uid comes in, they do
// not race with each other.
int TrafficController::deleteTagData(uint32_t tag, uid_t uid) {
    int res = 0;

    if (legacy_deleteTagData(tag, uid)) return -errno;
    if (!ebpfSupported) return 0;

    uint64_t curCookie = NONEXIST_COOKIE;
    uint64_t nextCookie = 0;
    UidTag tmp_uidtag;
    std::vector<uint64_t> cookieList;
    // First we go through the cookieTagMap to delete the target uid tag combination. Or delete all
    // the tags related to the uid if the tag is 0, we start the map iteration with a cookie of
    // INET_DIAG_NOCOOKIE because it's guaranteed that that will not be in the map.
    while (getNextMapKey(mCookieTagMap, &curCookie, &nextCookie) != -1) {
        res = findMapEntry(mCookieTagMap, &nextCookie, &tmp_uidtag);
        if (res < 0) {
            res = -errno;
            ALOGE("Failed to get tag info(cookie = %" PRIu64 ": %s\n", nextCookie, strerror(errno));
            // Continue to look for next entry.
            curCookie = nextCookie;
            continue;
        }

        if (tmp_uidtag.uid == uid && (tmp_uidtag.tag == tag || tag == 0)) {
            res = deleteMapEntry(mCookieTagMap, &nextCookie);
            if (res < 0 && errno != ENOENT) {
                res = -errno;
                ALOGE("Failed to delete data(cookie = %" PRIu64 "): %s\n", nextCookie,
                      strerror(errno));
            }
        } else {
            // Move forward to next cookie in the map.
            curCookie = nextCookie;
        }
    }

    // Now we go through the Tag stats map and delete the data entry with correct uid and tag
    // combination. Or all tag stats under that uid if the target tag is 0. The initial key is
    // set to the nonexist_statskey because it will never be in the map, and thus getNextMapKey will
    // return 0 and set nextKey to the first key in the map.
    struct StatsKey curKey, nextKey;
    curKey = android::bpf::NONEXISTENT_STATSKEY;
    while (getNextMapKey(mTagStatsMap, &curKey, &nextKey) != -1) {
        if (nextKey.uid == uid && (nextKey.tag == tag || tag == 0)) {
            res = deleteMapEntry(mTagStatsMap, &nextKey);
            if (res < 0 && errno != ENOENT) {
                // Skip the current entry if unexpected error happened.
                ALOGE("Failed to delete data(uid=%u, tag=%u): %s\n", nextKey.uid, nextKey.tag,
                      strerror(errno));
                curKey = nextKey;
            }
        } else {
            curKey = nextKey;
        }
    }

    // If the tag is not zero, we already deleted all the data entry required. If tag is 0, we also
    // need to delete the stats stored in uidStatsMap and counterSet map.
    if (tag != 0) return 0;

    res = deleteMapEntry(mUidCounterSetMap, &uid);
    if (res < 0 && errno != ENOENT) {
        ALOGE("Failed to delete counterSet data(uid=%u, tag=%u): %s\n", uid, tag, strerror(errno));
    }

    // For the uid stats deleted from the map, move them into a special
    // removed uid entry. The removed uid is stored in uid 0, tag 0 and
    // counterSet as COUNTERSETS_LIMIT.
    StatsKey removedStatsKey = {0, 0, COUNTERSETS_LIMIT, 0};
    StatsValue removedStatsTotal = {};
    res = findMapEntry(mUidStatsMap, &removedStatsKey, &removedStatsTotal);
    if (res < 0 && errno != ENOENT) {
        ALOGE("Failed to get stats of removed uid: %s", strerror(errno));
    }

    curKey = android::bpf::NONEXISTENT_STATSKEY;
    while (getNextMapKey(mUidStatsMap, &curKey, &nextKey) != -1) {
        if (nextKey.uid == uid) {
            StatsValue old_stats = {};
            res = findMapEntry(mUidStatsMap, &nextKey, &old_stats);
            if (res < 0) {
                if (errno != ENOENT) {
                    // if errno is ENOENT Somebody else deleted nextKey. Lookup the next key from
                    // curKey. If we have other error. Skip this key to avoid an infinite loop.
                    curKey = nextKey;
                }
                continue;
            }
            res = deleteMapEntry(mUidStatsMap, &nextKey);
            if (res < 0 && errno != ENOENT) {
                ALOGE("Failed to delete data(uid=%u, tag=%u): %s\n", nextKey.uid, nextKey.tag,
                      strerror(errno));
                curKey = nextKey;
                continue;
            }
            removedStatsTotal.rxTcpPackets += old_stats.rxTcpPackets;
            removedStatsTotal.rxTcpBytes += old_stats.rxTcpBytes;
            removedStatsTotal.txTcpPackets += old_stats.txTcpPackets;
            removedStatsTotal.txTcpBytes += old_stats.txTcpBytes;
            removedStatsTotal.rxUdpPackets += old_stats.rxUdpPackets;
            removedStatsTotal.rxUdpBytes += old_stats.rxUdpBytes;
            removedStatsTotal.txUdpPackets += old_stats.txUdpPackets;
            removedStatsTotal.txUdpBytes += old_stats.txUdpBytes;
            removedStatsTotal.rxOtherPackets += old_stats.rxOtherPackets;
            removedStatsTotal.rxOtherBytes += old_stats.rxOtherBytes;
            removedStatsTotal.txOtherPackets += old_stats.txOtherPackets;
            removedStatsTotal.txOtherBytes += old_stats.txOtherBytes;
        } else {
            curKey = nextKey;
        }
    }

    res = writeToMapEntry(mUidStatsMap, &removedStatsKey, &removedStatsTotal, BPF_ANY);
    if (res) {
        res = -errno;
        ALOGE("Failed to add deleting stats to removed uid: %s", strerror(errno));
    }
    return res;
}

}  // namespace net
}  // namespace android
