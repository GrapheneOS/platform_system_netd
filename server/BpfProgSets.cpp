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

#include "BpfProgSets.h"
#include "BpfUtils.h"
#include "TrafficController.h"
#include "netdutils/Slice.h"

using namespace android::net::bpf;
using android::netdutils::Slice;

namespace android {
namespace net {
namespace bpf_prog {

int loadIngressProg(int cookieTagMap, int uidStatsMap, int tagStatsMap, int uidCounterSetMap) {
    struct bpf_insn ingressProg[] = {

        /*
         * Save sk_buff for future usage. value stored in R6 to R10 will
         * not be reset after a bpf helper function call.
         */
        BPF_INS_BLK(REG_MOV64, BPF_REG_6, BPF_REG_1, 0, 0),
        /*
         * pc1: BPF_FUNC_get_socket_cookie takes one parameter,
         * R1: sk_buff
         */
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_socket_cookie),
        /* pc2-4: save &socketCookie to r7 for future usage*/
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_DW), BPF_REG_10, BPF_REG_0, -8, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_7, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_7, 0, 0, -8),
        /*
         * pc5-8: set up the registers for BPF_FUNC_map_lookup_elem,
         * it takes two parameters (R1: map_fd,  R2: &socket_cookie)
         */
        LOAD_MAP_FD(BPF_REG_1, (uint32_t)cookieTagMap),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_7, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        /*
         * pc9. if r0 != 0x0, go to pc+14, since we have the cookie
         * stored already
         * Otherwise do pc10-22 to setup a new data entry.
         */
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 9, 0), LOAD_MAP_FD(BPF_REG_7, uidStatsMap),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_6, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_socket_uid),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_0,
                    -16 + static_cast<__s16>(offsetof(struct UidTag, uid)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_W), BPF_REG_10, 0,
                    -16 + static_cast<__s16>(offsetof(struct UidTag, tag)), 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_8, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_8, 0, 0, -16),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 3, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_8, BPF_REG_0, 0, 0), LOAD_MAP_FD(BPF_REG_7, tagStatsMap),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_2, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct UidTag, uid)), 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_2, -132, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_2, 0, 0, -132),
        LOAD_MAP_FD(BPF_REG_1, uidCounterSetMap),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 2, 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_W), BPF_REG_10, 0,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, counterSet)), 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 2, 0),
        BPF_INS_BLK(MEM_LD(BPF_B), BPF_REG_1, BPF_REG_0, 0, 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_1,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, counterSet)), 0),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_2, BPF_REG_6,
                    static_cast<__s16>(offsetof(struct __sk_buff, ifindex)), 0),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_3, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct UidTag, uid)), 0),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_4, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct UidTag, tag)), 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_2,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, ifaceIndex)), 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_3,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, uid)), 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_4,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, tag)), 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_9, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_9, 0, 0, -32),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_7, 0, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_9, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 24, 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxTcpBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxTcpPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxUdpBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxUdpPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txTcpPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txTcpBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txUdpPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txUdpBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxOtherPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxOtherBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txOtherBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txOtherPackets)), 0),
        /*
         * add new map entry using BPF_FUNC_map_update_elem, it takes
         * 4 parameters (R1: map_fd, R2: &socket_cookie, R3: &stats,
         * R4: flags)
         */
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_7, 0, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_9, 0, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_3, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_3, 0, 0, -128),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_4, 0, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_7, 0, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_9, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 2, 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_0, 0, 0, 1), BPF_INS_BLK(PROG_EXIT, 0, 0, 0, 0),
        /*
         * pc24-30 update the packet info to a exist data entry, it can
         * be done by directly write to pointers instead of using
         * BPF_FUNC_map_update_elem helper function
         */
        BPF_INS_BLK(REG_MOV64, BPF_REG_9, BPF_REG_0, 0, 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_7, 0, 0, 1),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_8, BPF_REG_6,
                    static_cast<__s16>(offsetof(struct __sk_buff, len)), 0),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_1, BPF_REG_6,
                    static_cast<__s16>(offsetof(struct __sk_buff, protocol)), 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_1, 0, 7, htons(ETH_P_IP)),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_6, 0, 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_2, 0, 0, IPV4_TRANSPORT_PROTOCOL_OFFSET),
        BPF_INS_BLK(REG_MOV64, BPF_REG_3, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_3, 0, 0, -133),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_4, 0, 0, 1),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 7, 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_1, 0, 15, htons(ETH_P_IPV6)),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_6, 0, 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_2, 0, 0, IPV6_TRANSPORT_PROTOCOL_OFFSET),
        BPF_INS_BLK(REG_MOV64, BPF_REG_3, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_3, 0, 0, -133),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_4, 0, 0, 1),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
        BPF_INS_BLK(MEM_LD(BPF_B), BPF_REG_0, BPF_REG_10, -133, 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 3, IPPROTO_TCP),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_7,
                    static_cast<__s16>(offsetof(struct Stats, rxTcpPackets)), 0),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct Stats, rxTcpBytes)), 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 6, 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 3, IPPROTO_UDP),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_7,
                    static_cast<__s16>(offsetof(struct Stats, rxUdpPackets)), 0),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct Stats, rxUdpBytes)), 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 2, 0),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_7,
                    static_cast<__s16>(offsetof(struct Stats, rxOtherPackets)), 0),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct Stats, rxOtherBytes)), 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_0, 0, 0, 1), BPF_INS_BLK(PROG_EXIT, 0, 0, 0, 0),
    };
    Slice ingressInsn = Slice(ingressProg, sizeof(ingressProg));
    char bpf_log_buf[LOG_BUF_SIZE];
    Slice bpfLog = Slice(bpf_log_buf, sizeof(bpf_log_buf));

    return bpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, ingressInsn, "Apache", 0, bpfLog);
}

int loadEgressProg(int cookieTagMap, int uidStatsMap, int tagStatsMap, int uidCounterSetMap) {
    struct bpf_insn egressProg[] = {
        /*
         * Save sk_buff for future usage. value stored in R6 to R10 will
         * not be reset after a bpf helper function call.
         */
        BPF_INS_BLK(REG_MOV64, BPF_REG_6, BPF_REG_1, 0, 0),
        /*
         * pc1: BPF_FUNC_get_socket_cookie takes one parameter,
         * R1: sk_buff
         */
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_socket_cookie),
        /* pc2-4: save &socketCookie to r7 for future usage*/
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_DW), BPF_REG_10, BPF_REG_0, -8, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_7, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_7, 0, 0, -8),
        /*
         * pc5-8: set up the registers for BPF_FUNC_map_lookup_elem,
         * it takes two parameters (R1: map_fd,  R2: &socket_cookie)
         */
        LOAD_MAP_FD(BPF_REG_1, (uint32_t)cookieTagMap),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_7, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        /*
         * pc9. if r0 != 0x0, go to pc+14, since we have the cookie
         * stored already
         * Otherwise do pc10-22 to setup a new data entry.
         */
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 9, 0), LOAD_MAP_FD(BPF_REG_7, uidStatsMap),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_6, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_socket_uid),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_0,
                    -16 + static_cast<__s16>(offsetof(struct UidTag, uid)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_W), BPF_REG_10, 0,
                    -16 + static_cast<__s16>(offsetof(struct UidTag, tag)), 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_8, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_8, 0, 0, -16),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 3, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_8, BPF_REG_0, 0, 0), LOAD_MAP_FD(BPF_REG_7, tagStatsMap),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_2, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct UidTag, uid)), 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_2, -132, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_2, 0, 0, -132),
        LOAD_MAP_FD(BPF_REG_1, uidCounterSetMap),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 2, 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_W), BPF_REG_10, 0,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, counterSet)), 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 2, 0),
        BPF_INS_BLK(MEM_LD(BPF_B), BPF_REG_1, BPF_REG_0, 0, 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_1,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, counterSet)), 0),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_2, BPF_REG_6,
                    static_cast<__s16>(offsetof(struct __sk_buff, ifindex)), 0),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_3, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct UidTag, uid)), 0),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_4, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct UidTag, tag)), 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_2,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, ifaceIndex)), 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_3,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, uid)), 0),
        BPF_INS_BLK(MEM_SET_BY_REG(BPF_W), BPF_REG_10, BPF_REG_4,
                    -32 + static_cast<__s16>(offsetof(struct StatsKey, tag)), 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_9, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_9, 0, 0, -32),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_7, 0, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_9, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 24, 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxTcpBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxTcpPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxUdpBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxUdpPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txTcpPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txTcpBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txUdpPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txUdpBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxOtherPackets)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, rxOtherBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txOtherBytes)), 0),
        BPF_INS_BLK(MEM_SET_BY_VAL(BPF_DW), BPF_REG_10, 0,
                    -128 + static_cast<__s16>(offsetof(struct Stats, txOtherPackets)), 0),
        /*
         * add new map entry using BPF_FUNC_map_update_elem, it takes
         * 4 parameters (R1: map_fd, R2: &socket_cookie, R3: &stats,
         * R4: flags)
         */
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_7, 0, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_9, 0, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_3, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_3, 0, 0, -128),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_4, 0, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_7, 0, 0),
        BPF_INS_BLK(REG_MOV64, BPF_REG_2, BPF_REG_9, 0, 0),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 2, 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_0, 0, 0, 1), BPF_INS_BLK(PROG_EXIT, 0, 0, 0, 0),
        /*
         * pc24-30 update the packet info to a exist data entry, it can
         * be done by directly write to pointers instead of using
         * BPF_FUNC_map_update_elem helper function
         */
        BPF_INS_BLK(REG_MOV64, BPF_REG_9, BPF_REG_0, 0, 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_7, 0, 0, 1),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_8, BPF_REG_6,
                    static_cast<__s16>(offsetof(struct __sk_buff, len)), 0),
        BPF_INS_BLK(MEM_LD(BPF_W), BPF_REG_1, BPF_REG_6,
                    static_cast<__s16>(offsetof(struct __sk_buff, protocol)), 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_1, 0, 7, htons(ETH_P_IP)),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_6, 0, 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_2, 0, 0, IPV6_TRANSPORT_PROTOCOL_OFFSET),
        BPF_INS_BLK(REG_MOV64, BPF_REG_3, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_3, 0, 0, -133),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_4, 0, 0, 1),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 7, 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_1, 0, 15, htons(ETH_P_IPV6)),
        BPF_INS_BLK(REG_MOV64, BPF_REG_1, BPF_REG_6, 0, 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_2, 0, 0, IPV6_TRANSPORT_PROTOCOL_OFFSET),
        BPF_INS_BLK(REG_MOV64, BPF_REG_3, BPF_REG_10, 0, 0),
        BPF_INS_BLK(VAL_ALU64(BPF_ADD), BPF_REG_3, 0, 0, -133),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_4, 0, 0, 1),
        BPF_INS_BLK(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),
        BPF_INS_BLK(MEM_LD(BPF_B), BPF_REG_0, BPF_REG_10, -133, 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 3, IPPROTO_TCP),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_7,
                    static_cast<__s16>(offsetof(struct Stats, txTcpPackets)), 0),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct Stats, txTcpBytes)), 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 6, 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JNE), BPF_REG_0, 0, 3, IPPROTO_UDP),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_7,
                    static_cast<__s16>(offsetof(struct Stats, txUdpPackets)), 0),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct Stats, txUdpBytes)), 0),
        BPF_INS_BLK(VAL_ALU_JMP(BPF_JA), 0, 0, 2, 0),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_7,
                    static_cast<__s16>(offsetof(struct Stats, txOtherPackets)), 0),
        BPF_INS_BLK(REG_ATOMIC_ADD(BPF_DW), BPF_REG_9, BPF_REG_8,
                    static_cast<__s16>(offsetof(struct Stats, txOtherBytes)), 0),
        BPF_INS_BLK(VAL_MOV64, BPF_REG_0, 0, 0, 1), BPF_INS_BLK(PROG_EXIT, 0, 0, 0, 0),
    };

    Slice egressInsn = Slice(egressProg, sizeof(egressProg));
    char bpf_log_buf[LOG_BUF_SIZE];
    Slice bpfLog = Slice(bpf_log_buf, sizeof(bpf_log_buf));

    return bpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, egressInsn, "Apache", 0, bpfLog);
}

}  // namespace bpf_prog
}  // namespace net
}  // namespace android
