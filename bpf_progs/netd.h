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

/*
 * This h file together with netd.c is used for compiling the eBPF kernel
 * program.
 */

#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdbool.h>
#include <stdint.h>
#include "netdbpf/bpf_shared.h"

struct uid_tag {
    uint32_t uid;
    uint32_t tag;
};

struct stats_key {
    uint32_t uid;
    uint32_t tag;
    uint32_t counterSet;
    uint32_t ifaceIndex;
};

struct stats_value {
    uint64_t rxPackets;
    uint64_t rxBytes;
    uint64_t txPackets;
    uint64_t txBytes;
};

struct IfaceValue {
    char name[IFNAMSIZ];
};

// This is defined for cgroup bpf filter only.
#define BPF_PASS 1
#define BPF_DROP 0

// This is used for xt_bpf program only.
#define BPF_NOMATCH 0
#define BPF_MATCH 1

#define BPF_EGRESS 0
#define BPF_INGRESS 1

#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
#define IPV6_PROTO_OFF offsetof(struct ipv6hdr, nexthdr)
#define IPPROTO_IHL_OFF 0
#define TCP_FLAG_OFF 13
#define RST_OFFSET 2

struct bpf_map_def SEC("maps") cookie_tag_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint64_t),
        .value_size = sizeof(struct uid_tag),
        .max_entries = COOKIE_UID_MAP_SIZE,
};

struct bpf_map_def SEC("maps") uid_counterset_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint8_t),
        .max_entries = UID_COUNTERSET_MAP_SIZE,
};

struct bpf_map_def SEC("maps") app_uid_stats_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(struct stats_value),
        .max_entries = APP_STATS_MAP_SIZE,
};

struct bpf_map_def SEC("maps") stats_map_A = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct stats_key),
        .value_size = sizeof(struct stats_value),
        .max_entries = STATS_MAP_SIZE,
};

struct bpf_map_def SEC("maps") stats_map_B = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct stats_key),
        .value_size = sizeof(struct stats_value),
        .max_entries = STATS_MAP_SIZE,
};

struct bpf_map_def SEC("maps") iface_stats_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(struct stats_value),
        .max_entries = IFACE_STATS_MAP_SIZE,
};

struct bpf_map_def SEC("maps") configuration_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint8_t),
        .max_entries = CONFIGURATION_MAP_SIZE,
};

struct bpf_map_def SEC("maps") uid_owner_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(struct UidOwnerValue),
        .max_entries = UID_OWNER_MAP_SIZE,
};

struct bpf_map_def SEC("maps") iface_index_name_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(struct IfaceValue),
        .max_entries = IFACE_INDEX_NAME_MAP_SIZE,
};

static __always_inline int is_system_uid(uint32_t uid) {
    return (uid <= MAX_SYSTEM_UID) && (uid >= MIN_SYSTEM_UID);
}

static __always_inline inline void bpf_update_stats(struct __sk_buff* skb, struct bpf_map_def* map,
                                                    int direction, void* key) {
    struct stats_value* value;
    value = bpf_map_lookup_elem(map, key);
    if (!value) {
        struct stats_value newValue = {};
        bpf_map_update_elem(map, key, &newValue, BPF_NOEXIST);
        value = bpf_map_lookup_elem(map, key);
    }
    if (value) {
        if (direction == BPF_EGRESS) {
            __sync_fetch_and_add(&value->txPackets, 1);
            __sync_fetch_and_add(&value->txBytes, skb->len);
        } else if (direction == BPF_INGRESS) {
            __sync_fetch_and_add(&value->rxPackets, 1);
            __sync_fetch_and_add(&value->rxBytes, skb->len);
        }
    }
}

static inline bool skip_owner_match(struct __sk_buff* skb) {
    int offset = -1;
    int ret = 0;
    if (skb->protocol == ETH_P_IP) {
        offset = IP_PROTO_OFF;
        uint8_t proto, ihl;
        uint16_t flag;
        ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
        if (!ret) {
            if (proto == IPPROTO_ESP) {
                return true;
            } else if (proto == IPPROTO_TCP) {
                ret = bpf_skb_load_bytes(skb, IPPROTO_IHL_OFF, &ihl, 1);
                ihl = ihl & 0x0F;
                ret = bpf_skb_load_bytes(skb, ihl * 4 + TCP_FLAG_OFF, &flag, 1);
                if (ret == 0 && (flag >> RST_OFFSET & 1)) {
                    return true;
                }
            }
        }
    } else if (skb->protocol == ETH_P_IPV6) {
        offset = IPV6_PROTO_OFF;
        uint8_t proto;
        ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
        if (!ret) {
            if (proto == IPPROTO_ESP) {
                return true;
            } else if (proto == IPPROTO_TCP) {
                uint16_t flag;
                ret = bpf_skb_load_bytes(skb, sizeof(struct ipv6hdr) + TCP_FLAG_OFF, &flag, 1);
                if (ret == 0 && (flag >> RST_OFFSET & 1)) {
                    return true;
                }
            }
        }
    }
    return false;
}

static __always_inline BpfConfig getConfig(uint32_t configKey) {
    uint32_t mapSettingKey = configKey;
    BpfConfig* config = bpf_map_lookup_elem(&configuration_map, &mapSettingKey);
    if (!config) {
        // Couldn't read configuration entry. Assume everything is disabled.
        return DEFAULT_CONFIG;
    }
    return *config;
}

static inline int bpf_owner_match(struct __sk_buff* skb, uint32_t uid, int direction) {
    if (skip_owner_match(skb)) return BPF_PASS;

    if ((uid <= MAX_SYSTEM_UID) && (uid >= MIN_SYSTEM_UID)) return BPF_PASS;

    BpfConfig enabledRules = getConfig(UID_RULES_CONFIGURATION_KEY);

    struct UidOwnerValue* uidEntry = bpf_map_lookup_elem(&uid_owner_map, &uid);
    uint8_t uidRules = uidEntry ? uidEntry->rule : 0;
    uint32_t allowed_iif = uidEntry ? uidEntry->iif : 0;

    if (enabledRules) {
        if ((enabledRules & DOZABLE_MATCH) && !(uidRules & DOZABLE_MATCH)) {
            return BPF_DROP;
        }
        if ((enabledRules & STANDBY_MATCH) && (uidRules & STANDBY_MATCH)) {
            return BPF_DROP;
        }
        if ((enabledRules & POWERSAVE_MATCH) && !(uidRules & POWERSAVE_MATCH)) {
            return BPF_DROP;
        }
    }
    if (direction == BPF_INGRESS && (uidRules & IIF_MATCH)) {
        // Drops packets not coming from lo nor the whitelisted interface
        if (allowed_iif && skb->ifindex != 1 && skb->ifindex != allowed_iif) {
            return BPF_DROP;
        }
    }
    return BPF_PASS;
}

static __always_inline inline void update_stats_with_config(struct __sk_buff* skb, int direction,
                                                            void* key, uint8_t selectedMap) {
    if (selectedMap == SELECT_MAP_A) {
        bpf_update_stats(skb, &stats_map_A, direction, key);
    } else if (selectedMap == SELECT_MAP_B) {
        bpf_update_stats(skb, &stats_map_B, direction, key);
    }
}

static __always_inline inline int bpf_traffic_account(struct __sk_buff* skb, int direction) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    int match = bpf_owner_match(skb, sock_uid, direction);
    if ((direction == BPF_EGRESS) && (match == BPF_DROP)) {
        // If an outbound packet is going to be dropped, we do not count that
        // traffic.
        return match;
    }

    uint64_t cookie = bpf_get_socket_cookie(skb);
    struct uid_tag* utag = bpf_map_lookup_elem(&cookie_tag_map, &cookie);
    uint32_t uid, tag;
    if (utag) {
        uid = utag->uid;
        tag = utag->tag;
    } else {
        uid = sock_uid;
        tag = 0;
    }

    struct stats_key key = {.uid = uid, .tag = tag, .counterSet = 0, .ifaceIndex = skb->ifindex};

    uint8_t* counterSet = bpf_map_lookup_elem(&uid_counterset_map, &uid);
    if (counterSet) key.counterSet = (uint32_t)*counterSet;

    uint32_t mapSettingKey = CURRENT_STATS_MAP_CONFIGURATION_KEY;
    uint8_t* selectedMap = bpf_map_lookup_elem(&configuration_map, &mapSettingKey);
    if (!selectedMap) {
        return match;
    }

    if (tag) {
        update_stats_with_config(skb, direction, &key, *selectedMap);
    }

    key.tag = 0;
    update_stats_with_config(skb, direction, &key, *selectedMap);
    bpf_update_stats(skb, &app_uid_stats_map, direction, &uid);
    return match;
}
