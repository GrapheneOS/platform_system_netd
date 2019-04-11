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

#include "BandwidthController.h"
#include "FirewallController.h"
#include "NetlinkListener.h"
#include "Network.h"
#include "android-base/thread_annotations.h"
#include "android-base/unique_fd.h"
#include "bpf/BpfMap.h"
#include "netdbpf/bpf_shared.h"
#include "netdutils/DumpWriter.h"
#include "netdutils/StatusOr.h"
#include "utils/String16.h"

using android::bpf::BpfMap;
using android::bpf::IfaceValue;
using android::bpf::StatsKey;
using android::bpf::StatsValue;
using android::bpf::UidTag;

namespace android {
namespace net {

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
    int tagSocket(int sockFd, uint32_t tag, uid_t uid, uid_t callingUid);

    /*
     * The untag process is similiar to tag socket and both old qtaguid module and
     * new eBPF module have spinlock inside the kernel for concurrent update. No
     * external lock is required.
     */
    int untagSocket(int sockFd);

    /*
     * Similiar as above, no external lock required.
     */
    int setCounterSet(int counterSetNum, uid_t uid, uid_t callingUid);

    /*
     * When deleting a tag data, the qtaguid module will grab the spinlock of each
     * related rb_tree one by one and delete the tag information, counterSet
     * information, iface stats information and uid stats information one by one.
     * The new eBPF implementation is done similiarly by removing the entry on
     * each map one by one. And deleting processes are also protected by the
     * spinlock of the map. So no additional lock is required.
     */
    int deleteTagData(uint32_t tag, uid_t uid, uid_t callingUid);

    /*
     * Check if the current device have the bpf traffic stats accounting service
     * running.
     */
    bpf::BpfLevel getBpfLevel();

    /*
     * Swap the stats map config from current active stats map to the idle one.
     */
    netdutils::Status swapActiveStatsMap();

    /*
     * Add the interface name and index pair into the eBPF map.
     */
    int addInterface(const char* name, uint32_t ifaceIndex);

    int changeUidOwnerRule(ChildChain chain, const uid_t uid, FirewallRule rule, FirewallType type);

    int removeUidOwnerRule(const uid_t uid);

    int replaceUidOwnerMap(const std::string& name, bool isWhitelist,
                           const std::vector<int32_t>& uids);

    netdutils::Status updateOwnerMapEntry(UidOwnerMatchType match, uid_t uid, FirewallRule rule,
                                          FirewallType type);

    void dump(netdutils::DumpWriter& dw, bool verbose);

    netdutils::Status replaceRulesInMap(UidOwnerMatchType match, const std::vector<int32_t>& uids);

    netdutils::Status addUidInterfaceRules(const int ifIndex, const std::vector<int32_t>& uids);
    netdutils::Status removeUidInterfaceRules(const std::vector<int32_t>& uids);

    netdutils::Status updateUidOwnerMap(const std::vector<std::string>& appStrUids,
                                        BandwidthController::IptJumpOp jumpHandling,
                                        BandwidthController::IptOp op);
    static const String16 DUMP_KEYWORD;

    int toggleUidOwnerMap(ChildChain chain, bool enable);

    static netdutils::StatusOr<std::unique_ptr<NetlinkListenerInterface>> makeSkDestroyListener();

    void setPermissionForUids(int permission, const std::vector<uid_t>& uids);

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
    BpfMap<uint64_t, UidTag> mCookieTagMap;

    /*
     * mUidCounterSetMap: Store the counterSet of a specific uid.
     * Map Key: uint32 uid.
     * Map Value: uint32 counterSet specifies if the traffic is a background
     * or foreground traffic.
     */
    BpfMap<uint32_t, uint8_t> mUidCounterSetMap;

    /*
     * mAppUidStatsMap: Store the total traffic stats for a uid regardless of
     * tag, counterSet and iface. The stats is used by TrafficStats.getUidStats
     * API to return persistent stats for a specific uid since device boot.
     */
    BpfMap<uint32_t, StatsValue> mAppUidStatsMap;

    /*
     * mStatsMapA/mStatsMapB: Store the traffic statistics for a specific
     * combination of uid, tag, iface and counterSet. These two maps contain
     * both tagged and untagged traffic.
     * Map Key: Struct StatsKey contains the uid, tag, counterSet and ifaceIndex
     * information.
     * Map Value: struct Stats, contains packet count and byte count of each
     * transport protocol on egress and ingress direction.
     */
    BpfMap<StatsKey, StatsValue> mStatsMapA;

    BpfMap<StatsKey, StatsValue> mStatsMapB;

    /*
     * mIfaceIndexNameMap: Store the index name pair of each interface show up
     * on the device since boot. The interface index is used by the eBPF program
     * to correctly match the iface name when receiving a packet.
     */
    BpfMap<uint32_t, IfaceValue> mIfaceIndexNameMap;

    /*
     * mIfaceStataMap: Store per iface traffic stats gathered from xt_bpf
     * filter.
     */
    BpfMap<uint32_t, StatsValue> mIfaceStatsMap;

    /*
     * mConfigurationMap: Store the current network policy about uid filtering
     * and the current stats map in use. There are two configuration entries in
     * the map right now:
     * - Entry with UID_RULES_CONFIGURATION_KEY:
     *    Store the configuration for the current uid rules. It indicates the device
     *    is in doze/powersave/standby mode.
     * - Entry with CURRENT_STATS_MAP_CONFIGURATION_KEY:
     *    Stores the current live stats map that kernel program is writing to.
     *    Userspace can do scraping and cleaning job on the other one depending on the
     *    current configs.
     */
    BpfMap<uint32_t, uint8_t> mConfigurationMap GUARDED_BY(mOwnerMatchMutex);

    /*
     * mUidOwnerMap: Store uids that are used for bandwidth control uid match.
     */
    BpfMap<uint32_t, UidOwnerValue> mUidOwnerMap GUARDED_BY(mOwnerMatchMutex);

    /*
     * mUidOwnerMap: Store uids that are used for INTERNET permission check.
     */
    BpfMap<uint32_t, uint8_t> mUidPermissionMap;

    std::unique_ptr<NetlinkListenerInterface> mSkDestroyListener;

    netdutils::Status removeRule(BpfMap<uint32_t, UidOwnerValue>& map, uint32_t uid,
                                 UidOwnerMatchType match) REQUIRES(mOwnerMatchMutex);

    netdutils::Status addRule(BpfMap<uint32_t, UidOwnerValue>& map, uint32_t uid,
                              UidOwnerMatchType match, uint32_t iif = 0) REQUIRES(mOwnerMatchMutex);

    bpf::BpfLevel mBpfLevel;

    std::mutex mOwnerMatchMutex;

    netdutils::Status loadAndAttachProgram(bpf_attach_type type, const char* path, const char* name,
                                           base::unique_fd& cg_fd);

    netdutils::Status initMaps();

    // Keep track of uids that have permission UPDATE_DEVICE_STATS so we don't
    // need to call back to system server for permission check.
    std::set<uid_t> mPrivilegedUser;

    UidOwnerMatchType jumpOpToMatch(BandwidthController::IptJumpOp jumpHandling);

    bool hasUpdateDeviceStatsPermission(uid_t uid);
    // For testing
    friend class TrafficControllerTest;
};

}  // namespace net
}  // namespace android

#endif  // NETD_SERVER_TRAFFIC_CONTROLLER_H
