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

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include "bpf_kern.h"
#include "bpf_shared.h"

ELF_SEC(BPF_PROG_SEC_NAME)
int bpf_cgroup_egress(struct __sk_buff* skb) {
    uint64_t cookie = get_socket_cookie(skb);
    struct uid_tag* utag = find_map_entry(COOKIE_TAG_MAP, &cookie);
    uint32_t uid, tag;
    if (utag) {
        uid = utag->uid;
        tag = utag->tag;
    } else {
        uid = get_socket_uid(skb);
        tag = 0;
    }

    struct stats_key key = {.uid = uid, .tag = tag, .counterSet = 0, .ifaceIndex = skb->ifindex};

    uint32_t* counterSet;
    counterSet = find_map_entry(UID_COUNTERSET_MAP, &uid);
    if (counterSet) key.counterSet = *counterSet;

    int ret;
    if (tag) {
        struct stats_value* tagValue;
        tagValue = find_map_entry(TAG_STATS_MAP, &key);
        if (!tagValue) {
            struct stats_value newValue = {};
            write_to_map_entry(TAG_STATS_MAP, &key, &newValue, BPF_NOEXIST);
            tagValue = find_map_entry(TAG_STATS_MAP, &key);
        }
        if (tagValue) {
            __sync_fetch_and_add(&tagValue->txPackets, 1);
            __sync_fetch_and_add(&tagValue->txBytes, skb->len);
        }
    }

    key.tag = 0;
    struct stats_value* value;
    value = find_map_entry(UID_STATS_MAP, &key);
    if (!value) {
        struct stats_value newValue = {};
        write_to_map_entry(UID_STATS_MAP, &key, &newValue, BPF_NOEXIST);
        value = find_map_entry(UID_STATS_MAP, &key);
    }
    if (value) {
        __sync_fetch_and_add(&value->txPackets, 1);
        __sync_fetch_and_add(&value->txBytes, skb->len);
    }
    return BPF_PASS;
}
