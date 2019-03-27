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

#include "ClatUtils.h"

#include <errno.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG_TAG "ClatUtils"
#include <log/log.h>

#include "android-base/unique_fd.h"
#include "bpf/BpfUtils.h"
#include "netdbpf/bpf_shared.h"

namespace android {
namespace net {

int hardwareAddressType(const std::string& interface) {
    base::unique_fd ufd(socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0));

    if (ufd < 0) {
        const int err = errno;
        ALOGE("socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)");
        return -err;
    };

    struct ifreq ifr = {};
    // We use strncpy() instead of strlcpy() since kernel has to be able
    // to handle non-zero terminated junk passed in by userspace anyway,
    // and this way too long interface names (more than IFNAMSIZ-1 = 15
    // characters plus terminating NULL) will not get truncated to 15
    // characters and zero-terminated and thus potentially erroneously
    // match a truncated interface if one were to exist.
    strncpy(ifr.ifr_name, interface.c_str(), sizeof(ifr.ifr_name));

    if (ioctl(ufd, SIOCGIFHWADDR, &ifr, sizeof(ifr))) return -errno;

    return ifr.ifr_hwaddr.sa_family;
}

int getClatMapFd(void) {
    const int fd = bpf::bpfFdGet(CLAT_MAP_PATH, 0);
    return (fd == -1) ? -errno : fd;
}

int getClatProgFd(bool with_ethernet_header) {
    const int fd =
            bpf::bpfFdGet(with_ethernet_header ? CLAT_PROG_ETHER_PATH : CLAT_PROG_RAWIP_PATH, 0);
    return (fd == -1) ? -errno : fd;
}

}  // namespace net
}  // namespace android
