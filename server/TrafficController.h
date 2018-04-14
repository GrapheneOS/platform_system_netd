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

#ifndef NETD_SERVER_TRAFFIC_CONTROLLER_H
#define NETD_SERVER_TRAFFIC_CONTROLLER_H

#include <linux/bpf.h>

#include <netdutils/StatusOr.h>
#include "FirewallController.h"
#include "NetlinkListener.h"
#include "Network.h"
#include "android-base/thread_annotations.h"
#include "android-base/unique_fd.h"

// Since we cannot garbage collect the stats map since device boot, we need to make these maps as
// large as possible. The current rlimit of MEM_LOCK allows at most 10000 map entries for each
// stats map. In the old qtaguid module, we don't have a total limit for data entries but only have
// limitation of tags each uid can have. (default is 1024 in kernel);
// cookie_uid_map:      key:  8 bytes, value:  8 bytes, total:10000*8*2 bytes         =  160Kbytes
// uid_counter_set_map: key:  4 bytes, value:  4 bytes, total:10000*4*2 bytes         =   80Kbytes
// uid_stats_map:       key: 16 bytes, value: 32 bytes, total:10000*16+10000*32 bytes =  480Kbytes
// tag_stats_map:       key: 16 bytes, value: 32 bytes, total:10000*16+10000*32 bytes =  480Kbytes
// iface_index_name_map:key:  4 bytes, value: 32 bytes, total:10000*36 bytes          =  360Kbytes
// total:                                                                               1560Kbytes
constexpr const int COOKIE_UID_MAP_SIZE = 10000;
constexpr const int UID_COUNTERSET_MAP_SIZE = 10000;
constexpr const int UID_STATS_MAP_SIZE = 10000;
constexpr const int TAG_STATS_MAP_SIZE = 10000;
constexpr const int IFACE_INDEX_NAME_MAP_SIZE = 1000;
constexpr const int IFACE_STATS_MAP_SIZE = 1000;
constexpr const int UID_OWNER_MAP_SIZE = 10000;

constexpr const int COUNTERSETS_LIMIT = 2;

namespace android {
namespace net {

class DumpWriter;

class TrafficController {
  public:
    TrafficController();
    /*
     * Initialize the whole controller
     */
    netdutils::Status start();
    /*
     * Tag the socket with the specified tag and uid. In the qtaguid module, the
     * first tag request that grab the spinlock of rb_tree can update the tag
     * information first and other request need to wait until it finish. All the
     * tag request will be addressed in the order of they obtaining the spinlock.
     * In the eBPF implementation, the kernel will try to update the eBPF map
     * entry with the tag request. And the hashmap update process is protected by
     * the spinlock initialized with the map. So the behavior of two modules
     * should be the same. No additional lock needed.
     */
    int tagSocket(int sockFd, uint32_t tag, uid_t uid);

    /*
     * The untag process is similiar to tag socket and both old qtaguid module and
     * new eBPF module have spinlock inside the kernel for concurrent update. No
     * external lock is required.
     */
    int untagSocket(int sockFd);

    /*
     * Similiar as above, no external lock required.
     */
    int setCounterSet(int counterSetNum, uid_t uid);

    /*
     * When deleting a tag data, the qtaguid module will grab the spinlock of each
     * related rb_tree one by one and delete the tag information, counterSet
     * information, iface stats information and uid stats information one by one.
     * The new eBPF implementation is done similiarly by removing the entry on
     * each map one by one. And deleting processes are also protected by the
     * spinlock of the map. So no additional lock is required.
     */
    int deleteTagData(uint32_t tag, uid_t uid);

    /*
     * Check if the current device have the bpf traffic stats accounting service
     * running.
     */
    bool checkBpfStatsEnable();

    /*
     * Add the interface name and index pair into the eBPF map.
     */
    int addInterface(const char* name, uint32_t ifaceIndex);

    int changeUidOwnerRule(ChildChain chain, const uid_t uid, FirewallRule rule, FirewallType type);

    int removeUidOwnerRule(const uid_t uid);

    int replaceUidOwnerMap(const std::string& name, bool isWhitelist,
                           const std::vector<int32_t>& uids);

    int updateOwnerMapEntry(const base::unique_fd& map_fd, uid_t uid, FirewallRule rule,
                            FirewallType type);

    void dump(DumpWriter& dw, bool verbose);

    int replaceUidsInMap(const base::unique_fd& map_fd, const std::vector<int32_t> &uids,
                         FirewallRule rule, FirewallType type);

    static const String16 DUMP_KEYWORD;

    int toggleUidOwnerMap(ChildChain chain, bool enable);

  private:
    /*
     * mCookieTagMap: Store the corresponding tag and uid for a specific socket.
     * DO NOT hold any locks when modifying this map, otherwise when the untag
     * operation is waiting for a lock hold by other process and there are more
     * sockets being closed than can fit in the socket buffer of the netlink socket
     * that receives them, then the kernel will drop some of these sockets and we
     * won't delete their tags.
     * Map Key: uint64_t socket cookie
     * Map Value: struct UidTag, contains a uint32 uid and a uint32 tag.
     */
    base::unique_fd mCookieTagMap;

    /*
     * mUidCounterSetMap: Store the counterSet of a specific uid.
     * Map Key: uint32 uid.
     * Map Value: uint32 counterSet specifies if the traffic is a background
     * or foreground traffic.
     */
    base::unique_fd mUidCounterSetMap;

    /*
     * mUidStatsMap: Store the traffic statistics for a specific combination of
     * uid, iface and counterSet. We maintain this map in addition to
     * mTagStatsMap because we want to be able to track per-UID data usage even
     * if mTagStatsMap is full.
     * Map Key: Struct StatsKey contains the uid, counterSet and ifaceIndex
     * information. The Tag in the StatsKey should always be 0.
     * Map Value: struct Stats, contains packet count and byte count of each
     * transport protocol on egress and ingress direction.
     */
    base::unique_fd mUidStatsMap GUARDED_BY(mDeleteStatsMutex);

    /*
     * mTagStatsMap: Store the traffic statistics for a specific combination of
     * uid, tag, iface and counterSet. Only tagged socket stats should be stored
     * in this map.
     * Map Key: Struct StatsKey contains the uid, counterSet and ifaceIndex
     * information. The tag field should not be 0.
     * Map Value: struct Stats, contains packet count and byte count of each
     * transport protocol on egress and ingress direction.
     */
    base::unique_fd mTagStatsMap GUARDED_BY(mDeleteStatsMutex);


    /*
     * mIfaceIndexNameMap: Store the index name pair of each interface show up
     * on the device since boot. The interface index is used by the eBPF program
     * to correctly match the iface name when receiving a packet.
     */
    base::unique_fd mIfaceIndexNameMap;

    /*
     * mIfaceStataMap: Store per iface traffic stats gathered from xt_bpf
     * filter.
     */
    base::unique_fd mIfaceStatsMap;

    /*
     * mDozableUidMap: Store uids that have related rules in dozable mode owner match
     * chain.
     */
    base::unique_fd mDozableUidMap GUARDED_BY(mOwnerMatchMutex);

    /*
     * mStandbyUidMap: Store uids that have related rules in standby mode owner match
     * chain.
     */
    base::unique_fd mStandbyUidMap GUARDED_BY(mOwnerMatchMutex);

    /*
     * mPowerSaveUidMap: Store uids that have related rules in power save mode owner match
     * chain.
     */
    base::unique_fd mPowerSaveUidMap GUARDED_BY(mOwnerMatchMutex);

    std::unique_ptr<NetlinkListenerInterface> mSkDestroyListener;

    bool ebpfSupported;

    std::mutex mOwnerMatchMutex;

    // When aquiring both mOwnerMatchMutex and mDeleteStatsMutex,
    // mOwnerMatchMutex must be grabbed first to prevent protential deadlock.
    // This lock need to be hold when deleting from any stats map which we
    // can iterate which are uidStatsMap and tagStatsMap. We don't need this
    // lock to guard mUidCounterSetMap because we always directly look up /
    // write / delete the map by uid. Also we don't need this lock for
    // mCookieTagMap since the only time we need to iterate the map is
    // deleteTagStats and we don't care if we failed and started from the
    // beginning, since we will eventually scan through the map and delete all
    // target entries.
    std::mutex mDeleteStatsMutex;

    netdutils::Status loadAndAttachProgram(bpf_attach_type type, const char* path, const char* name,
                                           base::unique_fd& cg_fd);

    netdutils::Status initMaps();
    // For testing
    friend class TrafficControllerTest;
};

}  // namespace net
}  // namespace android

#endif  // NETD_SERVER_TRAFFIC_CONTROLLER_H
