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

#ifndef LOG_TAG
#define LOG_TAG "bpfloader"
#endif

#include <arpa/inet.h>
#include <elf.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/log.h>

#include <netdutils/Misc.h>
#include <netdutils/Slice.h>
#include "bpf/BpfUtils.h"
#include "bpf/bpf_shared.h"

using android::base::unique_fd;
using android::netdutils::Slice;

#define BPF_PROG_PATH "/system/etc/bpf"

#define INGRESS_PROG BPF_PROG_PATH"/cgroup_bpf_ingress_prog.o"
#define EGRESS_PROG BPF_PROG_PATH"/cgroup_bpf_egress_prog.o"
#define XT_BPF_INGRESS_PROG BPF_PROG_PATH "/xt_bpf_ingress_prog.o"
#define XT_BPF_EGRESS_PROG BPF_PROG_PATH "/xt_bpf_egress_prog.o"
#define MAP_LD_CMD_HEAD 0x18

#define FAIL(...)      \
    do {               \
        ((void)ALOG(LOG_ERROR, LOG_TAG, __VA_ARGS__)); \
        exit(-1);     \
    } while (0)

// The BPF instruction bytes that we need to replace. x is a placeholder (e.g., COOKIE_TAG_MAP).
#define MAP_SEARCH_PATTERN(x)             \
    {                                     \
        0x18, 0x01, 0x00, 0x00,           \
        (x)[0], (x)[1], (x)[2], (x)[3],   \
        0x00, 0x00, 0x00, 0x00,           \
        (x)[4], (x)[5], (x)[6], (x)[7]    \
    }

// The bytes we'll replace them with. x is the actual fd number for the map at runtime.
// The second byte is changed from 0x01 to 0x11 since 0x11 is the special command used
// for bpf map fd loading. The original 0x01 is only a normal load command.
#define MAP_REPLACE_PATTERN(x)            \
    {                                     \
        0x18, 0x11, 0x00, 0x00,           \
        (x)[0], (x)[1], (x)[2], (x)[3],   \
        0x00, 0x00, 0x00, 0x00,           \
        (x)[4], (x)[5], (x)[6], (x)[7]    \
    }

#define DECLARE_MAP(_mapFd, _mapPath)                             \
    unique_fd _mapFd(android::bpf::mapRetrieve((_mapPath), 0));   \
    if (_mapFd < 0) {                                             \
        FAIL("Failed to get map from %s", (_mapPath));            \
    }

#define MAP_CMD_SIZE 16
#define LOG_BUF_SIZE 65536

namespace android {
namespace bpf {

struct ReplacePattern {
    std::array<uint8_t, MAP_CMD_SIZE> search;
    std::array<uint8_t, MAP_CMD_SIZE> replace;

    ReplacePattern(uint64_t dummyFd, int realFd) {
        // Ensure that the fd numbers are big-endian.
        uint8_t beDummyFd[sizeof(uint64_t)];
        uint8_t beRealFd[sizeof(uint64_t)];
        for (size_t i = 0; i < sizeof(uint64_t); i++) {
            beDummyFd[i] = (dummyFd >> (i * 8)) & 0xFF;
            beRealFd[i] = (realFd >> (i * 8)) & 0xFF;
        }
        search = MAP_SEARCH_PATTERN(beDummyFd);
        replace = MAP_REPLACE_PATTERN(beRealFd);
    }
};

int loadProg(const char* path, const std::vector<ReplacePattern> &mapPatterns) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        FAIL("Failed to open %s program: %s", path, strerror(errno));
    }

    struct stat stat;
    if (fstat(fd, &stat)) FAIL("Fail to get file size");

    off_t fileLen = stat.st_size;
    char* baseAddr = (char*)mmap(NULL, fileLen, PROT_READ, MAP_PRIVATE, fd, 0);
    if (baseAddr == MAP_FAILED) FAIL("Failed to map the program into memory");

    if ((uint32_t)fileLen < sizeof(Elf64_Ehdr)) FAIL("file size too small for Elf64_Ehdr");

    Elf64_Ehdr* elf = (Elf64_Ehdr*)baseAddr;

    // Find section names string table. This is the section whose index is e_shstrndx.
    if (elf->e_shstrndx == SHN_UNDEF ||
        elf->e_shoff + (elf->e_shstrndx + 1) * sizeof(Elf64_Shdr) > (uint32_t)fileLen) {
        FAIL("cannot locate namesSection\n");
    }

    Elf64_Shdr* sections = (Elf64_Shdr*)(baseAddr + elf->e_shoff);

    Elf64_Shdr* namesSection = sections + elf->e_shstrndx;

    if (namesSection->sh_offset + namesSection->sh_size > (uint32_t)fileLen)
        FAIL("namesSection out of bound\n");

    const char* strTab = baseAddr + namesSection->sh_offset;
    void* progSection = nullptr;
    uint64_t progSize = 0;
    for (int i = 0; i < elf->e_shnum; i++) {
        Elf64_Shdr* section = sections + i;
        if (((char*)section - baseAddr) + sizeof(Elf64_Shdr) > (uint32_t)fileLen) {
            FAIL("next section is out of bound\n");
        }

        if (!strcmp(strTab + section->sh_name, BPF_PROG_SEC_NAME)) {
            progSection = baseAddr + section->sh_offset;
            progSize = (uint64_t)section->sh_size;
            break;
        }
    }

    if (!progSection) FAIL("program section not found");
    if ((char*)progSection - baseAddr + progSize > (uint32_t)fileLen)
        FAIL("programSection out of bound\n");

    char* prog = new char[progSize]();
    memcpy(prog, progSection, progSize);


    char* mapHead = prog;
    while ((uint64_t)(mapHead - prog + MAP_CMD_SIZE) < progSize) {
        // Scan the program, examining all possible places that might be the start of a map load
        // operation (i.e., all byes of value MAP_LD_CMD_HEAD).
        //
        // In each of these places, check whether it is the start of one of the patterns we want to
        // replace, and if so, replace it.
        mapHead = (char*)memchr(mapHead, MAP_LD_CMD_HEAD, progSize);
        if (!mapHead) break;
        for (const auto& pattern : mapPatterns) {
            if (!memcmp(mapHead, pattern.search.data(), MAP_CMD_SIZE)) {
                memcpy(mapHead, pattern.replace.data(), MAP_CMD_SIZE);
            }
        }
        mapHead++;
    }
    Slice insns = Slice(prog, progSize);
    char bpf_log_buf[LOG_BUF_SIZE];
    Slice bpfLog = Slice(bpf_log_buf, sizeof(bpf_log_buf));
    if (strcmp(path, XT_BPF_INGRESS_PROG) && strcmp(path, XT_BPF_EGRESS_PROG)) {
        return bpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, insns, "Apache 2.0", 0, bpfLog);
    }
    return bpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, insns, "Apache 2.0", 0, bpfLog);
}

int loadAndAttachProgram(bpf_attach_type type, const char* path, const char* name,
                         std::vector<ReplacePattern> mapPatterns) {
    unique_fd cg_fd(open(CGROUP_ROOT_PATH, O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    if (cg_fd < 0) {
        FAIL("Failed to open the cgroup directory");
    }

    unique_fd fd;
    if (type == BPF_CGROUP_INET_INGRESS) {
        fd.reset(loadProg(INGRESS_PROG, mapPatterns));
    } else if (type == BPF_CGROUP_INET_EGRESS) {
        fd.reset(loadProg(EGRESS_PROG, mapPatterns));
    } else if (!strcmp(name, "xt_bpf_ingress_prog")) {
        fd.reset(loadProg(XT_BPF_INGRESS_PROG, mapPatterns));
    } else if (!strcmp(name, "xt_bpf_egress_prog")) {
        fd.reset(loadProg(XT_BPF_EGRESS_PROG, mapPatterns));
    } else {
        FAIL("Unrecognized program type: %s", name);
    }

    if (fd < 0) {
        FAIL("load %s failed: %s", name, strerror(errno));
    }
    int ret = 0;
    if (type == BPF_CGROUP_INET_EGRESS || type == BPF_CGROUP_INET_INGRESS) {
        ret = attachProgram(type, fd, cg_fd);
        if (ret) {
            FAIL("%s attach failed: %s", name, strerror(errno));
        }
    }

    ret = mapPin(fd, path);
    if (ret) {
        FAIL("Pin %s as file %s failed: %s", name, path, strerror(errno));
    }
    return 0;
}

}  // namespace bpf
}  // namespace android

using android::bpf::BPF_EGRESS_PROG_PATH;
using android::bpf::BPF_INGRESS_PROG_PATH;
using android::bpf::COOKIE_TAG_MAP_PATH;
using android::bpf::DOZABLE_UID_MAP_PATH;
using android::bpf::IFACE_STATS_MAP_PATH;
using android::bpf::POWERSAVE_UID_MAP_PATH;
using android::bpf::STANDBY_UID_MAP_PATH;
using android::bpf::TAG_STATS_MAP_PATH;
using android::bpf::UID_COUNTERSET_MAP_PATH;
using android::bpf::UID_STATS_MAP_PATH;
using android::bpf::XT_BPF_EGRESS_PROG_PATH;
using android::bpf::XT_BPF_INGRESS_PROG_PATH;
using android::bpf::ReplacePattern;

static void usage(void) {
    ALOGE( "Usage: ./bpfloader [-i] [-e]\n"
           "   -i load ingress bpf program\n"
           "   -e load egress bpf program\n"
           "   -p load prerouting xt_bpf program\n"
           "   -m load mangle xt_bpf program\n");
}

int main(int argc, char** argv) {
    int ret = 0;
    DECLARE_MAP(cookieTagMap, COOKIE_TAG_MAP_PATH);
    DECLARE_MAP(uidCounterSetMap, UID_COUNTERSET_MAP_PATH);
    DECLARE_MAP(uidStatsMap, UID_STATS_MAP_PATH);
    DECLARE_MAP(tagStatsMap, TAG_STATS_MAP_PATH);
    DECLARE_MAP(ifaceStatsMap, IFACE_STATS_MAP_PATH);
    DECLARE_MAP(dozableUidMap, DOZABLE_UID_MAP_PATH);
    DECLARE_MAP(standbyUidMap, STANDBY_UID_MAP_PATH);
    DECLARE_MAP(powerSaveUidMap, POWERSAVE_UID_MAP_PATH);

    const std::vector<ReplacePattern> mapPatterns = {
        ReplacePattern(COOKIE_TAG_MAP, cookieTagMap.get()),
        ReplacePattern(UID_COUNTERSET_MAP, uidCounterSetMap.get()),
        ReplacePattern(UID_STATS_MAP, uidStatsMap.get()),
        ReplacePattern(TAG_STATS_MAP, tagStatsMap.get()),
        ReplacePattern(IFACE_STATS_MAP, ifaceStatsMap.get()),
        ReplacePattern(DOZABLE_UID_MAP, dozableUidMap.get()),
        ReplacePattern(STANDBY_UID_MAP, standbyUidMap.get()),
        ReplacePattern(POWERSAVE_UID_MAP, powerSaveUidMap.get()),
    };

    int opt;
    bool doIngress = false, doEgress = false, doPrerouting = false, doMangle = false;
    while ((opt = getopt(argc, argv, "iepm")) != -1) {
        switch (opt) {
            case 'i':
                doIngress = true;
                break;
            case 'e':
                doEgress = true;
                break;
            case 'p':
                doPrerouting = true;
                break;
            case 'm':
                doMangle = true;
                break;
            default:
                usage();
                FAIL("unknown argument %c", opt);
        }
    }
    if (doIngress) {
        ret = android::bpf::loadAndAttachProgram(BPF_CGROUP_INET_INGRESS, BPF_INGRESS_PROG_PATH,
                                                 "ingress_prog", mapPatterns);
        if (ret) {
            FAIL("Failed to set up ingress program");
        }
    }
    if (doEgress) {
        ret = android::bpf::loadAndAttachProgram(BPF_CGROUP_INET_EGRESS, BPF_EGRESS_PROG_PATH,
                                                 "egress_prog", mapPatterns);
        if (ret) {
            FAIL("Failed to set up ingress program");
        }
    }
    if (doPrerouting) {
        ret = android::bpf::loadAndAttachProgram(
            MAX_BPF_ATTACH_TYPE, XT_BPF_INGRESS_PROG_PATH, "xt_bpf_ingress_prog", mapPatterns);
        if (ret) {
            FAIL("Failed to set up xt_bpf program");
        }
    }
    if (doMangle) {
        ret = android::bpf::loadAndAttachProgram(
            MAX_BPF_ATTACH_TYPE, XT_BPF_EGRESS_PROG_PATH, "xt_bpf_egress_prog", mapPatterns);
        if (ret) {
            FAIL("Failed to set up xt_bpf program");
        }
    }
    return ret;
}
