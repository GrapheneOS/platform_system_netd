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

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "android-base/unique_fd.h"
#include "netdutils/Slice.h"
#include "netdutils/StatusOr.h"

#define ptr_to_u64(x) ((uint64_t)(uintptr_t)x)
#define DEFAULT_LOG_LEVEL 1

/* instruction set for bpf program */

#define MEM_LD(SIZE) (BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM)
#define MEM_SET_BY_REG(SIZE) (BPF_STX | BPF_SIZE(SIZE) | BPF_MEM)
#define MEM_SET_BY_VAL(SIZE) (BPF_ST | BPF_SIZE(SIZE) | BPF_MEM)
#define PROG_EXIT (BPF_JMP | BPF_EXIT)
#define REG_ALU64(OP) (BPF_ALU64 | BPF_OP(OP) | BPF_X)
#define REG_ALU32(OP) (BPF_ALU | BPF_OP(OP) | BPF_X)
#define REG_ALU_JMP(OP) (BPF_JMP | BPF_OP(OP) | BPF_X)
#define REG_ATOMIC_ADD(SIZE) (BPF_STX | BPF_SIZE(SIZE) | BPF_XADD)
#define REG_MOV64 (BPF_ALU64 | BPF_MOV | BPF_X)
#define REG_MOV32 (BPF_ALU | BPF_MOV | BPF_X)
#define SKB_LD(SIZE) (BPF_LD | BPF_SIZE(SIZE) | BPF_ABS)
#define VAL_ALU64(OP) (BPF_ALU64 | BPF_OP(OP) | BPF_K)
#define VAL_ALU32(OP) (BPF_ALU | BPF_OP(OP) | BPF_K)
#define VAL_ALU_JMP(OP) (BPF_JMP | BPF_OP(OP) | BPF_K)
#define VAL_MOV64 (BPF_ALU64 | BPF_MOV | BPF_K)
#define VAL_MOV32 (BPF_ALU | BPF_MOV | BPF_K)

/* Raw code statement block */

#define BPF_INS_BLK(CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn){                       \
        .code = (CODE), .dst_reg = (DST), .src_reg = (SRC), .off = (OFF), .imm = (IMM)})

#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif

#define LOAD_MAP_FD(DST, MAP_FD)                                                                 \
    BPF_INS_BLK(BPF_LD | BPF_DW | BPF_IMM, DST, BPF_PSEUDO_MAP_FD, 0, (__s32)((__u32)(MAP_FD))), \
        BPF_INS_BLK(0, 0, 0, 0, (__s32)(((__u64)(MAP_FD)) >> 32))

namespace android {
namespace bpf {

//The following definition and the new_bpf_attr struct is from upstream header
//v4.15 but not in bionic uapi header yet since 4.15 is still at rc stage.
//TODO: delete these definition once bionic uapi header get updated.

#ifndef BPF_OBJ_NAME_LEN
#define BPF_OBJ_NAME_LEN 16U
#else
#error clean up the definition here.
#endif

/* Flags for accessing BPF object */
#ifndef BPF_F_RDONLY
#define BPF_F_RDONLY            (1U << 3)
#else
#error clean up the definition here
#endif

#ifndef BPF_F_WRONLY
#define BPF_F_WRONLY            (1U << 4)
#else
#error clean up the definition here
#endif

union new_bpf_attr {
    struct { /* anonymous struct used by BPF_MAP_CREATE command */
        __u32   map_type;       /* one of enum bpf_map_type */
        __u32   key_size;       /* size of key in bytes */
        __u32   value_size;     /* size of value in bytes */
        __u32   max_entries;    /* max number of entries in a map */
        __u32   map_flags;      /* BPF_MAP_CREATE related
                                 * flags defined above.
                                 */
        __u32   inner_map_fd;   /* fd pointing to the inner map */
        __u32   numa_node;      /* numa node (effective only if
                                 * BPF_F_NUMA_NODE is set).
                                 */
        char    map_name[BPF_OBJ_NAME_LEN];
    };

    struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
        __u32           map_fd;
        __aligned_u64   key;
        union {
                __aligned_u64 value;
                __aligned_u64 next_key;
        };
        __u64           flags;
    };

    struct { /* anonymous struct used by BPF_PROG_LOAD command */
        __u32           prog_type;      /* one of enum bpf_prog_type */
        __u32           insn_cnt;
        __aligned_u64   insns;
        __aligned_u64   license;
        __u32           log_level;      /* verbosity level of verifier */
        __u32           log_size;       /* size of user buffer */
        __aligned_u64   log_buf;        /* user supplied buffer */
        __u32           kern_version;   /* checked when prog_type=kprobe */
        __u32           prog_flags;
        char            prog_name[BPF_OBJ_NAME_LEN];
        __u32           prog_ifindex;   /* ifindex of netdev to prep for */
    };

    struct { /* anonymous struct used by BPF_OBJ_* commands */
        __aligned_u64   pathname;
        __u32           bpf_fd;
        __u32           file_flags;
    };

    struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
        __u32           target_fd;      /* container object to attach to */
        __u32           attach_bpf_fd;  /* eBPF program to attach */
        __u32           attach_type;
        __u32           attach_flags;
    };
} __attribute__((aligned(8)));

int createMap(bpf_map_type map_type, uint32_t key_size, uint32_t value_size,
              uint32_t max_entries, uint32_t map_flags);
int writeToMapEntry(const base::unique_fd& map_fd, void* key, void* value, uint64_t flags);
int findMapEntry(const base::unique_fd& map_fd, void* key, void* value);
int deleteMapEntry(const base::unique_fd& map_fd, void* key);
int getNextMapKey(const base::unique_fd& map_fd, void* key, void* next_key);
int bpfProgLoad(bpf_prog_type prog_type, netdutils::Slice bpf_insns, const char* license,
                uint32_t kern_version, netdutils::Slice bpf_log);
int mapPin(const base::unique_fd& map_fd, const char* pathname);
int mapRetrieve(const char* pathname, uint32_t flags);
int attachProgram(bpf_attach_type type, uint32_t prog_fd, uint32_t cg_fd);
int detachProgram(bpf_attach_type type, uint32_t cg_fd);
netdutils::StatusOr<base::unique_fd> setUpBPFMap(uint32_t key_size, uint32_t value_size,
                                                 uint32_t map_size, const char* path,
                                                 bpf_map_type map_type);
}  // namespace bpf
}  // namespace android
