/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef NETDBPF_BPF_NET_HELPERS_H
#define NETDBPF_BPF_NET_HELPERS_H

#include <linux/bpf.h>
#include <linux/if_packet.h>
#include <stdbool.h>
#include <stdint.h>

static inline __always_inline __unused bool is_received_skb(struct __sk_buff* skb) {
    return skb->pkt_type == PACKET_HOST || skb->pkt_type == PACKET_BROADCAST ||
           skb->pkt_type == PACKET_MULTICAST;
}

#endif  // NETDBPF_BPF_NET_HELPERS_H
