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
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <mutex>
#include <unordered_set>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <logwrap/logwrap.h>
#include <netdutils/StatusOr.h>

#include <netdutils/Misc.h>
#include <netdutils/Syscalls.h>
#include "TrafficController.h"
#include "bpf/BpfUtils.h"
#include "bpf/bpf_shared.h"

#include "DumpWriter.h"
#include "FirewallController.h"
#include "InterfaceController.h"
#include "NetlinkListener.h"
#include "qtaguid/qtaguid.h"

using namespace android::bpf;

namespace android {
namespace net {

using base::StringPrintf;
using base::unique_fd;
using base::Join;
using netdutils::extract;
using netdutils::Slice;
using netdutils::sSyscalls;
using netdutils::Status;
using netdutils::statusFromErrno;
using netdutils::StatusOr;
using netdutils::status::ok;

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

Status changeOwnerAndMode(const char* path, gid_t group, const char* debugName, bool netdOnly) {
    int ret = chown(path, AID_ROOT, group);
    if (ret != 0) return statusFromErrno(errno, StringPrintf("change %s group failed", debugName));

    if (netdOnly) {
        ret = chmod(path, S_IRWXU);
    } else {
        // Allow both netd and system server to obtain map fd from the path.
        // chmod doesn't grant permission to all processes in that group to
        // read/write the bpf map. They still need correct sepolicy to
        // read/write the map.
        ret = chmod(path, S_IRWXU | S_IRGRP);
    }
    if (ret != 0) return statusFromErrno(errno, StringPrintf("change %s mode failed", debugName));
    return netdutils::status::ok;
}

TrafficController::TrafficController() {
    ebpfSupported = hasBpfSupport();
}

Status initialOwnerMap(const unique_fd& map_fd, const std::string mapName) {
    uint32_t mapSettingKey = UID_MAP_ENABLED;
    uint32_t defaultMapState = 0;
    int ret = writeToMapEntry(map_fd, &mapSettingKey, &defaultMapState, BPF_NOEXIST);
    // If it is already exist, it might be a runtime restart and we just keep
    // the old state.
    if (ret && errno != EEXIST) {
        return statusFromErrno(errno, "Fail to set the initial state of " + mapName);
    }
    return netdutils::status::ok;
}

Status TrafficController::initMaps() {
    std::lock_guard<std::mutex> guard(mOwnerMatchMutex);
    ASSIGN_OR_RETURN(mCookieTagMap,
                     setUpBPFMap(sizeof(uint64_t), sizeof(struct UidTag), COOKIE_UID_MAP_SIZE,
                                 COOKIE_TAG_MAP_PATH, BPF_MAP_TYPE_HASH));

    RETURN_IF_NOT_OK(changeOwnerAndMode(COOKIE_TAG_MAP_PATH, AID_NET_BW_ACCT, "CookieTagMap",
                                        false));

    ASSIGN_OR_RETURN(mUidCounterSetMap,
                     setUpBPFMap(sizeof(uint32_t), sizeof(uint32_t), UID_COUNTERSET_MAP_SIZE,
                                 UID_COUNTERSET_MAP_PATH, BPF_MAP_TYPE_HASH));
    RETURN_IF_NOT_OK(changeOwnerAndMode(UID_COUNTERSET_MAP_PATH, AID_NET_BW_ACCT,
                                        "UidCounterSetMap", false));

    ASSIGN_OR_RETURN(mUidStatsMap,
                     setUpBPFMap(sizeof(struct StatsKey), sizeof(struct StatsValue),
                                 UID_STATS_MAP_SIZE, UID_STATS_MAP_PATH, BPF_MAP_TYPE_HASH));
    RETURN_IF_NOT_OK(changeOwnerAndMode(UID_STATS_MAP_PATH, AID_NET_BW_STATS, "UidStatsMap",
                                        false));

    ASSIGN_OR_RETURN(mTagStatsMap,
                     setUpBPFMap(sizeof(struct StatsKey), sizeof(struct StatsValue),
                                 TAG_STATS_MAP_SIZE, TAG_STATS_MAP_PATH, BPF_MAP_TYPE_HASH));
    RETURN_IF_NOT_OK(changeOwnerAndMode(TAG_STATS_MAP_PATH, AID_NET_BW_STATS, "TagStatsMap",
                                        false));

    ASSIGN_OR_RETURN(mIfaceIndexNameMap,
                     setUpBPFMap(sizeof(uint32_t), IFNAMSIZ, IFACE_INDEX_NAME_MAP_SIZE,
                                 IFACE_INDEX_NAME_MAP_PATH, BPF_MAP_TYPE_HASH));
    RETURN_IF_NOT_OK(changeOwnerAndMode(IFACE_INDEX_NAME_MAP_PATH, AID_NET_BW_STATS,
                                        "IfaceIndexNameMap", false));

    ASSIGN_OR_RETURN(mDozableUidMap,
                     setUpBPFMap(sizeof(uint32_t), sizeof(uint8_t), UID_OWNER_MAP_SIZE,
                                 DOZABLE_UID_MAP_PATH, BPF_MAP_TYPE_HASH));
    RETURN_IF_NOT_OK(changeOwnerAndMode(DOZABLE_UID_MAP_PATH, AID_ROOT, "DozableUidMap", true));
    RETURN_IF_NOT_OK(initialOwnerMap(mDozableUidMap, "DozableUidMap"));

    ASSIGN_OR_RETURN(mStandbyUidMap,
                     setUpBPFMap(sizeof(uint32_t), sizeof(uint8_t), UID_OWNER_MAP_SIZE,
                                 STANDBY_UID_MAP_PATH, BPF_MAP_TYPE_HASH));
    RETURN_IF_NOT_OK(changeOwnerAndMode(STANDBY_UID_MAP_PATH, AID_ROOT, "StandbyUidMap", true));
    RETURN_IF_NOT_OK(initialOwnerMap(mStandbyUidMap, "StandbyUidMap"));

    ASSIGN_OR_RETURN(mPowerSaveUidMap,
                     setUpBPFMap(sizeof(uint32_t), sizeof(uint8_t), UID_OWNER_MAP_SIZE,
                                 POWERSAVE_UID_MAP_PATH, BPF_MAP_TYPE_HASH));
    RETURN_IF_NOT_OK(changeOwnerAndMode(POWERSAVE_UID_MAP_PATH, AID_ROOT, "PowerSaveUidMap", true));
    RETURN_IF_NOT_OK(initialOwnerMap(mPowerSaveUidMap, "PowerSaveUidMap"));

    ASSIGN_OR_RETURN(mIfaceStatsMap,
                     setUpBPFMap(sizeof(uint32_t), sizeof(struct StatsValue), IFACE_STATS_MAP_SIZE,
                                 IFACE_STATS_MAP_PATH, BPF_MAP_TYPE_HASH));
    RETURN_IF_NOT_OK(changeOwnerAndMode(IFACE_STATS_MAP_PATH, AID_NET_BW_STATS, "IfaceStatsMap",
                                        false));
    return netdutils::status::ok;
}

Status TrafficController::start() {

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

    RETURN_IF_NOT_OK(initMaps());

    // Fetch the list of currently-existing interfaces. At this point NetlinkHandler is
    // already running, so it will call addInterface() when any new interface appears.
    std::map<std::string, uint32_t> ifacePairs;
    ASSIGN_OR_RETURN(ifacePairs, InterfaceController::getIfaceList());
    for (const auto& ifacePair:ifacePairs) {
        addInterface(ifacePair.first.c_str(), ifacePair.second);
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

    int* status = nullptr;

    std::vector<const char*> prog_args{
        "/system/bin/bpfloader",
    };
    int ret = access(BPF_INGRESS_PROG_PATH, R_OK);
    if (ret != 0 && errno == ENOENT) {
        prog_args.push_back((char*)"-i");
    }
    ret = access(BPF_EGRESS_PROG_PATH, R_OK);
    if (ret != 0 && errno == ENOENT) {
        prog_args.push_back((char*)"-e");
    }
    ret = access(XT_BPF_INGRESS_PROG_PATH, R_OK);
    if (ret != 0 && errno == ENOENT) {
        prog_args.push_back((char*)"-p");
    }
    ret = access(XT_BPF_EGRESS_PROG_PATH, R_OK);
    if (ret != 0 && errno == ENOENT) {
        prog_args.push_back((char*)"-m");
    }

    if (prog_args.size() == 1) {
        // all program are loaded already.
        return netdutils::status::ok;
    }

    prog_args.push_back(nullptr);
    ret = android_fork_execvp(prog_args.size(), (char**)prog_args.data(), status, false, true);
    if (ret) {
        ret = errno;
        ALOGE("failed to execute %s: %s", prog_args[0], strerror(errno));
        return statusFromErrno(ret, "run bpf loader failed");
    }
    return netdutils::status::ok;
}

int TrafficController::tagSocket(int sockFd, uint32_t tag, uid_t uid) {
    if (!ebpfSupported) {
        if (legacy_tagSocket(sockFd, tag, uid)) return -errno;
        return 0;
    }

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
    if (!ebpfSupported) {
        if (legacy_untagSocket(sockFd)) return -errno;
        return 0;
    }
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
    if (!ebpfSupported) {
        if (legacy_setCounterSet(counterSetNum, uid)) return -errno;
        return 0;
    }

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

    if (!ebpfSupported) {
        if (legacy_deleteTagData(tag, uid)) return -errno;
        return 0;
    }

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
            removedStatsTotal.rxPackets += old_stats.rxPackets;
            removedStatsTotal.rxBytes += old_stats.rxBytes;
            removedStatsTotal.txPackets += old_stats.txPackets;
            removedStatsTotal.txBytes += old_stats.txBytes;
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

int TrafficController::addInterface(const char* name, uint32_t ifaceIndex) {
    int res = 0;
    if (!ebpfSupported) return res;

    char ifaceName[IFNAMSIZ];
    if (ifaceIndex == 0) {
        ALOGE("Unknow interface %s(%d)", name, ifaceIndex);
        return -1;
    }

    strlcpy(ifaceName, name, sizeof(ifaceName));
    res = writeToMapEntry(mIfaceIndexNameMap, &ifaceIndex, ifaceName, BPF_ANY);
    if (res) {
        res = -errno;
        ALOGE("Failed to add iface %s(%d): %s", name, ifaceIndex, strerror(errno));
    }
    return res;
}

int TrafficController::updateOwnerMapEntry(const base::unique_fd& map_fd, uid_t uid,
                                           FirewallRule rule, FirewallType type) {
    int res = 0;
    if (uid == NONEXISTENT_UID) {
        ALOGE("This uid should never exist in maps: %u", uid);
        return -EINVAL;
    }

    if (uid == UID_MAP_ENABLED) {
        ALOGE("This uid is reserved for map state");
        return -EINVAL;
    }

    if ((rule == ALLOW && type == WHITELIST) || (rule == DENY && type == BLACKLIST)) {
        uint8_t flag = (type == WHITELIST) ? BPF_PASS : BPF_DROP;
        res = writeToMapEntry(map_fd, &uid, &flag, BPF_ANY);
        if (res) {
            res = -errno;
            ALOGE("Failed to add owner rule(uid: %u): %s", uid, strerror(errno));
        }
    } else if ((rule == ALLOW && type == BLACKLIST) || (rule == DENY && type == WHITELIST)) {
        res = deleteMapEntry(map_fd, &uid);
        if (res) {
            res = -errno;
            ALOGE("Failed to delete owner rule(uid: %u): %s", uid, strerror(errno));
        }
    } else {
        //Cannot happen.
        return -EINVAL;
    }
    return res;
}

int TrafficController::changeUidOwnerRule(ChildChain chain, uid_t uid, FirewallRule rule,
                                          FirewallType type) {
    std::lock_guard<std::mutex> guard(mOwnerMatchMutex);
    if (!ebpfSupported) {
        ALOGE("bpf is not set up, should use iptables rule");
        return -ENOSYS;
    }
    switch (chain) {
        case DOZABLE:
            return updateOwnerMapEntry(mDozableUidMap, uid, rule, type);
        case STANDBY:
            return updateOwnerMapEntry(mStandbyUidMap, uid, rule, type);
        case POWERSAVE:
            return updateOwnerMapEntry(mPowerSaveUidMap, uid, rule, type);
        case NONE:
        default:
            return -EINVAL;
    }
}

int TrafficController::replaceUidsInMap(const base::unique_fd& map_fd,
                                        const std::vector<int32_t> &uids,
                                        FirewallRule rule, FirewallType type) {
    std::set<int32_t> uidSet(uids.begin(), uids.end());
    std::vector<uint32_t> uidsToDelete;
    auto getUidsToDelete = [&uidsToDelete, &uidSet](void *key, const base::unique_fd&) {
        uint32_t uid = *(uint32_t *)key;
        if (uid != UID_MAP_ENABLED && uidSet.find((int32_t)uid) == uidSet.end()) {
            uidsToDelete.push_back(uid);
        }
        return 0;
    };
    uint32_t nonExistentKey = NONEXISTENT_UID;
    uint8_t dummyValue;
    int ret = bpfIterateMap(nonExistentKey, dummyValue, map_fd, getUidsToDelete);

    if (ret)  return ret;

    for(auto uid : uidsToDelete) {
        if(deleteMapEntry(map_fd, &uid)) {
            ret = -errno;
            ALOGE("Delete uid(%u) from owner Map %d failed: %s", uid, map_fd.get(),
                  strerror(errno));
            return -errno;
        }
    }

    for (auto uid : uids) {
        ret = updateOwnerMapEntry(map_fd, uid, rule, type);
        if (ret) {
            ALOGE("Failed to add owner rule(uid: %u, map: %d)", uid, map_fd.get());
            return ret;
        }
    }
    return 0;
}

int TrafficController::replaceUidOwnerMap(const std::string& name, bool isWhitelist,
                                          const std::vector<int32_t>& uids) {
    std::lock_guard<std::mutex> guard(mOwnerMatchMutex);
    FirewallRule rule;
    FirewallType type;
    if (isWhitelist) {
        type = WHITELIST;
        rule = ALLOW;
    } else {
        type = BLACKLIST;
        rule = DENY;
    }
    int ret;
    if (!name.compare(FirewallController::LOCAL_DOZABLE)) {
        ret = replaceUidsInMap(mDozableUidMap, uids, rule, type);
    } else if (!name.compare(FirewallController::LOCAL_STANDBY)) {
        ret = replaceUidsInMap(mStandbyUidMap, uids, rule, type);
    } else if (!name.compare(FirewallController::LOCAL_POWERSAVE)) {
        ret = replaceUidsInMap(mPowerSaveUidMap, uids, rule, type);
    } else {
        ALOGE("unknown chain name: %s", name.c_str());
        return -EINVAL;
    }
    if (ret) {
        ALOGE("Failed to clean up chain: %s: %s", name.c_str(), strerror(ret));
        return ret;
    }
    return 0;
}

int TrafficController::toggleUidOwnerMap(ChildChain chain, bool enable) {
    std::lock_guard<std::mutex> guard(mOwnerMatchMutex);
    uint32_t keyUid = UID_MAP_ENABLED;
    uint8_t mapState = enable ? 1 : 0;
    int ret;
    switch (chain) {
        case DOZABLE:
            ret = writeToMapEntry(mDozableUidMap, &keyUid, &mapState, BPF_EXIST);
            break;
        case STANDBY:
            ret = writeToMapEntry(mStandbyUidMap, &keyUid, &mapState, BPF_EXIST);
            break;
        case POWERSAVE:
            ret = writeToMapEntry(mPowerSaveUidMap, &keyUid, &mapState, BPF_EXIST);
            break;
        default:
            return -EINVAL;
    }
    if (ret) {
        ret = -errno;
        ALOGE("Failed to toggleUidOwnerMap(%d): %s", chain, strerror(errno));
    }
    return ret;
}

bool TrafficController::checkBpfStatsEnable() {
    return ebpfSupported;
}

std::string getProgramStatus(const char *path) {
    int ret = access(path, R_OK);
    if (ret == 0) {
        return StringPrintf("OK");
    }
    if (ret != 0 && errno == ENOENT) {
        return StringPrintf("program is missing at: %s", path);
    }
    return StringPrintf("check Program %s error: %s", path, strerror(errno));
}

std::string getMapStatus(const unique_fd& map_fd, const char *path) {
    if (map_fd.get() < 0) {
        return StringPrintf("map fd lost");
    }
    if (access(path, F_OK) != 0) {
        return StringPrintf("map not pinned to location: %s", path);
    }
    return StringPrintf("OK");
}

void dumpBpfMap(std::string mapName, DumpWriter& dw, const std::string& header) {
    dw.blankline();
    dw.println("%s:", mapName.c_str());
    if(!header.empty()) {
        dw.println(header.c_str());
    }
}

const String16 TrafficController::DUMP_KEYWORD = String16("trafficcontroller");

void TrafficController::dump(DumpWriter& dw, bool verbose) {
    std::lock_guard<std::mutex> guard(mOwnerMatchMutex);
    dw.incIndent();
    dw.println("TrafficController");

    dw.incIndent();
    dw.println("BPF module status: %s", ebpfSupported? "ON" : "OFF");

    if (!ebpfSupported)
        return;

    dw.blankline();
    dw.println("mCookieTagMap status: %s",
               getMapStatus(mCookieTagMap, COOKIE_TAG_MAP_PATH).c_str());
    dw.println("mUidCounterSetMap status: %s",
               getMapStatus(mUidCounterSetMap, UID_COUNTERSET_MAP_PATH).c_str());
    dw.println("mUidStatsMap status: %s", getMapStatus(mUidStatsMap, UID_STATS_MAP_PATH).c_str());
    dw.println("mTagStatsMap status: %s", getMapStatus(mTagStatsMap, TAG_STATS_MAP_PATH).c_str());
    dw.println("mIfaceIndexNameMap status: %s",
               getMapStatus(mIfaceIndexNameMap, IFACE_INDEX_NAME_MAP_PATH).c_str());
    dw.println("mIfaceStatsMap status: %s",
               getMapStatus(mIfaceStatsMap, IFACE_STATS_MAP_PATH).c_str());
    dw.println("mDozableUidMap status: %s",
               getMapStatus(mDozableUidMap, DOZABLE_UID_MAP_PATH).c_str());
    dw.println("mStandbyUidMap status: %s",
               getMapStatus(mStandbyUidMap, STANDBY_UID_MAP_PATH).c_str());
    dw.println("mPowerSaveUidMap status: %s",
               getMapStatus(mPowerSaveUidMap, POWERSAVE_UID_MAP_PATH).c_str());

    dw.blankline();
    dw.println("Cgroup ingress program status: %s",
               getProgramStatus(BPF_INGRESS_PROG_PATH).c_str());
    dw.println("Cgroup egress program status: %s", getProgramStatus(BPF_EGRESS_PROG_PATH).c_str());
    dw.println("xt_bpf ingress program status: %s",
               getProgramStatus(XT_BPF_INGRESS_PROG_PATH).c_str());
    dw.println("xt_bpf egress program status: %s",
               getProgramStatus(XT_BPF_EGRESS_PROG_PATH).c_str());

    if(!verbose) return;

    dw.blankline();
    dw.println("BPF map content:");

    dw.incIndent();

    // Print CookieTagMap content.
    dumpBpfMap("mCookieTagMap", dw, "");
    const uint64_t nonExistentCookie = NONEXIST_COOKIE;
    UidTag dummyUidTag;
    auto printCookieTagInfo = [&dw](void *key, void *value) {
        UidTag uidTagEntry = *(UidTag *) value;
        uint64_t cookie = *(uint64_t *) key;
        dw.println("cookie=%" PRIu64 " tag=0x%x uid=%u", cookie, uidTagEntry.tag, uidTagEntry.uid);
        return 0;
    };
    int ret = bpfIterateMapWithValue(nonExistentCookie, dummyUidTag, mCookieTagMap,
                                     printCookieTagInfo);
    if (ret) {
        dw.println("mCookieTagMap print end with error: %s", strerror(-ret));
    }

    // Print UidCounterSetMap Content
    dumpBpfMap("mUidCounterSetMap", dw, "");
    const uint32_t nonExistentUid = NONEXISTENT_UID;
    uint32_t dummyUidInfo;
    auto printUidInfo = [&dw](void *key, void *value) {
        uint8_t setting = *(uint8_t *) value;
        uint32_t uid = *(uint32_t *) key;
        dw.println("%u %u", uid, setting);
        return 0;
    };
    ret = bpfIterateMapWithValue(nonExistentUid, dummyUidInfo, mUidCounterSetMap, printUidInfo);
    if (ret) {
       dw.println("mUidCounterSetMap print end with error: %s", strerror(-ret));
    }

    // Print uidStatsMap content
    std::string statsHeader = StringPrintf("ifaceIndex ifaceName tag_hex uid_int cnt_set rxBytes"
                                           " rxPackets txBytes txPackets");
    dumpBpfMap("mUidStatsMap", dw, statsHeader);
    const struct StatsKey nonExistentStatsKey = NONEXISTENT_STATSKEY;
    struct StatsValue dummyStatsValue;
    auto printStatsInfo = [&dw, this](void *key, void *value) {
        StatsValue statsEntry = *(StatsValue *) value;
        StatsKey keyInfo = *(StatsKey *) key;
        char ifname[IFNAMSIZ];
        uint32_t ifIndex = keyInfo.ifaceIndex;
        if (bpf::findMapEntry(mIfaceIndexNameMap, &ifIndex, &ifname) < 0) {
            strlcpy(ifname, "unknown", sizeof(ifname));
        }
        dw.println("%u %s 0x%x %u %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64, ifIndex, ifname,
                   keyInfo.tag, keyInfo.uid, keyInfo.counterSet, statsEntry.rxBytes,
                   statsEntry.rxPackets, statsEntry.txBytes, statsEntry.txPackets);
        return 0;
    };
    ret = bpfIterateMapWithValue(nonExistentStatsKey, dummyStatsValue, mUidStatsMap,
                                 printStatsInfo);
    if (ret) {
        dw.println("mUidStatsMap print end with error: %s", strerror(-ret));
    }

    // Print TagStatsMap content.
    dumpBpfMap("mTagStatsMap", dw, statsHeader);
    ret = bpfIterateMapWithValue(nonExistentStatsKey, dummyStatsValue, mTagStatsMap,
                                 printStatsInfo);
    if (ret) {
        dw.println("mTagStatsMap print end with error: %s", strerror(-ret));
    }

    // Print ifaceIndexToNameMap content.
    dumpBpfMap("mIfaceIndexNameMap", dw, "");
    uint32_t nonExistentIface = NONEXISTENT_IFACE_STATS_KEY;
    char dummyIface[IFNAMSIZ];
    auto printIfaceNameInfo = [&dw](void *key, void *value) {
        char *ifname = (char *) value;
        uint32_t ifaceIndex = *(uint32_t *)key;
        dw.println("ifaceIndex=%u ifaceName=%s", ifaceIndex, ifname);
        return 0;
    };
    ret = bpfIterateMapWithValue(nonExistentIface, dummyIface, mIfaceIndexNameMap,
                               printIfaceNameInfo);
    if (ret) {
        dw.println("mIfaceIndexNameMap print end with error: %s", strerror(-ret));
    }

    // Print ifaceStatsMap content
    std::string ifaceStatsHeader = StringPrintf("ifaceIndex ifaceName rxBytes rxPackets txBytes"
                                                " txPackets");
    dumpBpfMap("mIfaceStatsMap:", dw, ifaceStatsHeader);
    auto printIfaceStatsInfo = [&dw, this] (void *key, void *value) {
        StatsValue statsEntry = *(StatsValue *) value;
        uint32_t ifaceIndex = *(uint32_t *) key;
        char ifname[IFNAMSIZ];
        if (bpf::findMapEntry(mIfaceIndexNameMap, key, ifname) < 0) {
            strlcpy(ifname, "unknown", sizeof(ifname));
        }
        dw.println("%u %s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64, ifaceIndex, ifname,
                   statsEntry.rxBytes, statsEntry.rxPackets, statsEntry.txBytes,
                   statsEntry.txPackets);
        return 0;
    };
    ret = bpfIterateMapWithValue(nonExistentIface, dummyStatsValue, mIfaceStatsMap,
                                 printIfaceStatsInfo);
    if (ret) {
        dw.println("mIfaceStatsMap print end with error: %s", strerror(-ret));
    }

    // Print owner match uid maps
    uint8_t dummyOwnerInfo;
    dumpBpfMap("mDozableUidMap", dw, "");
    ret = bpfIterateMapWithValue(nonExistentUid, dummyOwnerInfo, mDozableUidMap, printUidInfo);
    if (ret) {
        dw.println("mDozableUidMap print end with error: %s", strerror(-ret));
    }

    dumpBpfMap("mStandbyUidMap", dw, "");
    ret = bpfIterateMapWithValue(nonExistentUid, dummyOwnerInfo, mStandbyUidMap, printUidInfo);
    if (ret) {
        dw.println("mDozableUidMap print end with error: %s", strerror(-ret));
    }

    dumpBpfMap("mPowerSaveUidMap", dw, "");
    ret = bpfIterateMapWithValue(nonExistentUid, dummyOwnerInfo, mPowerSaveUidMap, printUidInfo);
    if (ret) {
        dw.println("mDozableUidMap print end with error: %s", strerror(-ret));
    }

    dw.decIndent();

    dw.decIndent();

    dw.decIndent();

}

}  // namespace net
}  // namespace android
