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
#include <stdint.h>

#define ELF_SEC(NAME) __attribute__((section(NAME), used))

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

/* helper functions called from eBPF programs written in C */
static void* (*find_map_entry)(uint64_t map, void* key) = (void*)BPF_FUNC_map_lookup_elem;
static int (*write_to_map_entry)(uint64_t map, void* key, void* value,
                                 uint64_t flags) = (void*)BPF_FUNC_map_update_elem;
static int (*delete_map_entry)(uint64_t map, void* key) = (void*)BPF_FUNC_map_delete_elem;
static uint64_t (*get_socket_cookie)(struct __sk_buff* skb) = (void*)BPF_FUNC_get_socket_cookie;
static uint32_t (*get_socket_uid)(struct __sk_buff* skb) = (void*)BPF_FUNC_get_socket_uid;
static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to,
                                 int len) = (void*)BPF_FUNC_skb_load_bytes;

#define BPF_PASS 1
#define BPF_DROP 0
