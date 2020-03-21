/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <linux/if.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include "bpf_helpers.h"
#include "bpf_net_helpers.h"
#include "netdbpf/bpf_shared.h"

DEFINE_BPF_MAP_GRW(tether_ingress_map, HASH, TetherIngressKey, TetherIngressValue, 64,
                   AID_NETWORK_STACK)

// Tethering stats, indexed by upstream interface.
DEFINE_BPF_MAP_GRW(tether_stats_map, HASH, uint32_t, TetherStatsValue, IFACE_STATS_MAP_SIZE,
                   AID_NETWORK_STACK)

static inline __always_inline int do_forward(struct __sk_buff* skb, bool is_ethernet) {
    int l2_header_size = is_ethernet ? sizeof(struct ethhdr) : 0;
    void* data = (void*)(long)skb->data;
    const void* data_end = (void*)(long)skb->data_end;
    struct ethhdr* eth = is_ethernet ? data : NULL;  // used iff is_ethernet
    struct ipv6hdr* ip6 = is_ethernet ? (void*)(eth + 1) : data;

    // Must be meta-ethernet IPv6 frame
    if (skb->protocol != htons(ETH_P_IPV6)) return TC_ACT_OK;

    // Must have (ethernet and) ipv6 header
    if (data + l2_header_size + sizeof(*ip6) > data_end) return TC_ACT_OK;

    // Ethertype - if present - must be IPv6
    if (is_ethernet && (eth->h_proto != htons(ETH_P_IPV6))) return TC_ACT_OK;

    // IP version must be 6
    if (ip6->version != 6) return TC_ACT_OK;

    // Cannot decrement during forward if already zero or would be zero,
    // Let the kernel's stack handle these cases and generate appropriate ICMP errors.
    if (ip6->hop_limit <= 1) return TC_ACT_OK;

    TetherIngressKey k = {
            .iif = skb->ifindex,
            .neigh6 = ip6->daddr,
    };

    TetherIngressValue* v = bpf_tether_ingress_map_lookup_elem(&k);

    // If we don't find any offload information then simply let the core stack handle it...
    if (!v) return TC_ACT_OK;

    uint32_t stat_k = skb->ifindex;

    TetherStatsValue* stat_v = bpf_tether_stats_map_lookup_elem(&stat_k);

    // If we don't have anywhere to put stats, create an empty entry.
    if (!stat_v) {
        TetherStatsValue emptyStats = {};
        bpf_tether_stats_map_update_elem(&stat_k, &emptyStats, BPF_NOEXIST);
        stat_v = bpf_tether_stats_map_lookup_elem(&stat_k);
    }

    // If we *still* don't have anywhere to put stats, then abort...
    if (!stat_v) return TC_ACT_OK;

    // This is approximate handling of tcp/ip overhead for incoming LRO/GRO packets:
    // mtu of 1500 is not necessarily correct, but worst case we simply undercount,
    // which is still better then not accounting for this overhead at all.
    // Note: this really shouldn't be device mtu at all, but rather should be derived
    // from this particular connection's mss - which requires a much newer kernel.
    const int mtu = 1500;
    uint64_t packets = 1;
    uint64_t bytes = skb->len;
    if (bytes > mtu) {
        const bool is_ipv6 = (skb->protocol == htons(ETH_P_IPV6));
        const int ip_overhead = (is_ipv6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
        const int tcp_overhead = ip_overhead + sizeof(struct tcphdr) + 12;
        const int mss = mtu - tcp_overhead;
        const uint64_t payload = bytes - tcp_overhead;
        packets = (payload + mss - 1) / mss;
        bytes = tcp_overhead * packets + payload;
    }

    if (!is_ethernet) {
        is_ethernet = true;
        l2_header_size = sizeof(struct ethhdr);
        // Try to inject an ethernet header, and simply return if we fail
        if (bpf_skb_change_head(skb, l2_header_size, /*flags*/ 0)) {
            __sync_fetch_and_add(&stat_v->rxErrors, 1);
            return TC_ACT_OK;
        }

        // bpf_skb_change_head() invalidates all pointers - reload them
        data = (void*)(long)skb->data;
        data_end = (void*)(long)skb->data_end;
        eth = data;
        ip6 = (void*)(eth + 1);

        // I do not believe this can ever happen, but keep the verifier happy...
        if (data + l2_header_size + sizeof(*ip6) > data_end) return TC_ACT_SHOT;
    };

    // CHECKSUM_COMPLETE is a 16-bit one's complement sum,
    // thus corrections for it need to be done in 16-byte chunks at even offsets.
    // IPv6 nexthdr is at offset 6, while hop limit is at offset 7
    uint8_t old_hl = ip6->hop_limit;
    --ip6->hop_limit;
    uint8_t new_hl = ip6->hop_limit;

    // bpf_csum_update() always succeeds if the skb is CHECKSUM_COMPLETE and returns an error
    // (-ENOTSUPP) if it isn't.
    bpf_csum_update(skb, 0xFFFF - ntohs(old_hl) + ntohs(new_hl));

    __sync_fetch_and_add(&stat_v->rxPackets, packets);
    __sync_fetch_and_add(&stat_v->rxBytes, bytes);

    // Overwrite any mac header with the new one
    *eth = v->macHeader;

    // Redirect to forwarded interface.
    //
    // Note that bpf_redirect() cannot fail unless you pass invalid flags.
    // The redirect actually happens after the ebpf program has already terminated,
    // and can fail for example for mtu reasons at that point in time, but there's nothing
    // we can do about it here.
    return bpf_redirect(v->oif, 0 /* this is effectively BPF_F_EGRESS */);
}

SEC("schedcls/ingress/tether_ether")
int sched_cls_ingress_tether_ether(struct __sk_buff* skb) {
    return do_forward(skb, true);
}

SEC("schedcls/ingress/tether_rawip")
int sched_cls_ingress_tether_rawip(struct __sk_buff* skb) {
    return do_forward(skb, false);
}

LICENSE("Apache 2.0");
