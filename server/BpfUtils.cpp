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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "BpfUtils.h"
#include "TrafficController.h"
#include "netdutils/Slice.h"

#define LOG_TAG "Netd"
#include "log/log.h"

using android::netdutils::Slice;

namespace android {
namespace net {
namespace bpf {

int bpf(int cmd, Slice bpfAttr) {
    return syscall(__NR_bpf, cmd, bpfAttr.base(), bpfAttr.size());
}

int createMap(bpf_map_type map_type, uint32_t key_size, uint32_t value_size,
              uint32_t max_entries, uint32_t map_flags) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = map_flags;

    return bpf(BPF_MAP_CREATE, Slice(&attr, sizeof(attr)));
}

int writeToMapEntry(int fd, void* key, void* value, uint64_t flags) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = ptr_to_u64(key);
    attr.value = ptr_to_u64(value);
    attr.flags = flags;

    return bpf(BPF_MAP_UPDATE_ELEM, Slice(&attr, sizeof(attr)));
}

int findMapEntry(uint32_t fd, void* key, void* value) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = ptr_to_u64(key);
    attr.value = ptr_to_u64(value);

    return bpf(BPF_MAP_LOOKUP_ELEM, Slice(&attr, sizeof(attr)));
}

int deleteMapEntry(uint32_t fd, void* key) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = ptr_to_u64(key);

    return bpf(BPF_MAP_DELETE_ELEM, Slice(&attr, sizeof(attr)));
}

int getNextMapKey(uint32_t fd, void* key, void* next_key) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = ptr_to_u64(key);
    attr.next_key = ptr_to_u64(next_key);

    return bpf(BPF_MAP_GET_NEXT_KEY, Slice(&attr, sizeof(attr)));
}

int bpfProgLoad(bpf_prog_type prog_type, Slice bpf_insns, const char* license,
                uint32_t kern_version, Slice bpf_log) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = prog_type;
    attr.insns = ptr_to_u64(bpf_insns.base());
    attr.insn_cnt = bpf_insns.size() / sizeof(struct bpf_insn);
    attr.license = ptr_to_u64((void*)license);
    attr.log_buf = ptr_to_u64(bpf_log.base());
    attr.log_size = bpf_log.size();
    attr.log_level = DEFAULT_LOG_LEVEL;
    attr.kern_version = kern_version;
    int ret = bpf(BPF_PROG_LOAD, Slice(&attr, sizeof(attr)));

    if (ret < 0) ALOGE("program load failed:\n%s", bpf_log.base());
    return ret;
}

int mapPin(uint32_t fd, const char* pathname) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64((void*)pathname);
    attr.bpf_fd = fd;

    return bpf(BPF_OBJ_PIN, Slice(&attr, sizeof(attr)));
}

int mapRetrieve(const char* pathname) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64((void*)pathname);
    // TODO: Add the file flag field back after the kernel changes for bpf obj flags is merged and
    // the android uapi header is updated.
    return bpf(BPF_OBJ_GET, Slice(&attr, sizeof(attr)));
}

int attachProgram(bpf_attach_type type, uint32_t prog_fd, uint32_t cg_fd) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = cg_fd;
    attr.attach_bpf_fd = prog_fd;
    attr.attach_type = type;

    return bpf(BPF_PROG_ATTACH, Slice(&attr, sizeof(attr)));
}

int detachProgram(bpf_attach_type type, uint32_t cg_fd) {
    bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.target_fd = cg_fd;
    attr.attach_type = type;

    return bpf(BPF_PROG_DETACH, Slice(&attr, sizeof(attr)));
}

int setUpBPFMap(uint32_t key_size, uint32_t value_size, uint32_t map_size, const char* path,
                bpf_map_type map_type) {
    int ret;
    int map_fd = -1;
    ret = access(path, R_OK);
    /* Check the pinned location first to check if the map is already there.
     * otherwise create a new one.
     */
    if (ret == 0) {
        map_fd = mapRetrieve(path);
        if (map_fd < 0)
            ALOGE("pinned map not accessable or not exist: %s(%s)\n", strerror(errno), path);
    } else if (ret < 0 && errno == ENOENT) {
        map_fd = createMap(map_type, key_size, value_size, map_size, 0);
        if (map_fd < 0) {
            ret = -errno;
            ALOGE("map create failed!: %s(%s)\n", strerror(errno), path);
            return ret;
        }
        ret = mapPin(map_fd, path);
        if (ret) {
            ret = -errno;
            ALOGE("bpf map pin(%d, %s): %s\n", map_fd, path, strerror(errno));
            return ret;
        }
    } else {
        ret = -errno;
        ALOGE("pinned map not accessable: %s(%s)\n", strerror(errno), path);
        return ret;
    }
    return map_fd;
}

}  // namespace bpf
}  // namespace net
}  // namespace android
