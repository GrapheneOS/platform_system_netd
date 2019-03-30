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

#include <linux/pkt_cls.h>
#include "bpf_helpers.h"
#include "netdbpf/bpf_shared.h"

struct bpf_map_def SEC("maps") clat_ingress_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ClatIngressKey),
        .value_size = sizeof(struct ClatIngressValue),
        .max_entries = 16,
};

SEC("schedcls/ingress/clat_ether")
int sched_cls_ingress_clat_ether(struct __sk_buff* skb) {
    return TC_ACT_OK;
}

SEC("schedcls/ingress/clat_rawip")
int sched_cls_ingress_clat_rawip(struct __sk_buff* skb) {
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Apache 2.0";
