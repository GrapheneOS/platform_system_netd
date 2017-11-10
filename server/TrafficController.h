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

#include "Network.h"

#ifndef DEFAULT_OVERFLOWUID
#define DEFAULT_OVERFLOWUID 65534
#endif

#define LOG_BUF_SIZE 65536

#define BPF_PATH "/sys/fs/bpf"

constexpr const char* COOKIE_UID_MAP_PATH = BPF_PATH "/traffic_cookie_uid_map";
constexpr const char* UID_COUNTERSET_MAP_PATH = BPF_PATH "/traffic_uid_counterSet_map";
constexpr const char* UID_STATS_MAP_PATH = BPF_PATH "/traffic_uid_stats_map";
constexpr const char* TAG_STATS_MAP_PATH = BPF_PATH "/traffic_tag_stats_map";

constexpr const char* CGROUP_ROOT_PATH = "/dev/cg2_bpf";

constexpr const int IPV6_TRANSPORT_PROTOCOL_OFFSET = 6;
constexpr const int IPV4_TRANSPORT_PROTOCOL_OFFSET = 9;

// TODO: change it to a reasonable size.
constexpr const int COOKIE_UID_MAP_SIZE = 100;
constexpr const int UID_COUNTERSET_MAP_SIZE = 100;
constexpr const int UID_STATS_MAP_SIZE = 100;
constexpr const int TAG_STATS_MAP_SIZE = 100;

constexpr const int COUNTERSETS_LIMIT = 2;

namespace android {
namespace net {

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

struct Stats {
    uint64_t rxTcpPackets;
    uint64_t rxTcpBytes;
    uint64_t txTcpPackets;
    uint64_t txTcpBytes;
    uint64_t rxUdpPackets;
    uint64_t rxUdpBytes;
    uint64_t txUdpPackets;
    uint64_t txUdpBytes;
    uint64_t rxOtherPackets;
    uint64_t rxOtherBytes;
    uint64_t txOtherPackets;
    uint64_t txOtherBytes;
};

class TrafficController {
  public:
    /*
     * Initialize the whole controller
     */
    int start();
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

    /* Old api for debugging the qtaguid module. When the pacifier is on, all
     * the command will return successful but no actual action is taken.
     */
    int setPacifier(uint32_t on);

  private:
    /*
     * mCookieTagMap: Store the corresponding tag and uid for a specific socket.
     * Map Key: uint64_t socket cookie
     * Map Value: struct UidTag, contains a uint32 uid and a uint32 tag.
     */
    int mCookieTagMap;

    /*
     * mUidCounterSetMap: Store the counterSet of a specific uid.
     * Map Key: uint32 uid.
     * Map Value: uint32 counterSet specifies if the traffic is a background
     * or foreground traffic.
     */
    int mUidCounterSetMap;

    /*
     * mUidStatsMap: Store the traffic statistics for a specific combination of
     * uid, iface and counterSet.
     * Map Key: Struct StatsKey contains the uid, counterSet and ifaceIndex
     * information. The Tag in the StatsKey should always be 0.
     * Map Value: struct Stats, contains packet count and byte count of each
     * transport protocol on egress and ingress direction.
     */
    int mUidStatsMap;

    /*
     * mTagStatsMap: Store the traffic statistics for a specific combination of
     * uid, tag, iface and counterSet. Only tagged socket stats should be stored
     * in this map.
     * Map Key: Struct StatsKey contains the uid, counterSet and ifaceIndex
     * information. The tag field should not be 0.
     * Map Value: struct Stats, contains packet count and byte count of each
     * transport protocol on egress and ingress direction.
     */
    int mTagStatsMap;

    /*
     * IngressProgram: Program attached to the root cgroup directory and
     * monitoring the traffic on ingress side.
     */
    int mInProgFd;

    /*
     * EgressProgram: Program attached to the root cgroup directory and
     * monitoring the traffic on egress side.
     */
    int mOutProgFd;
    bool ebpfSupported;
};

}  // namespace net
}  // namespace android

#endif  // NETD_SERVER_TRAFFIC_CONTROLLER_H
