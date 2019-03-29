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
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define LOG_TAG "ClatUtils"
#include <log/log.h>

#include "NetlinkCommands.h"
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

// TODO: use //system/netd/server/NetlinkCommands.cpp:openNetlinkSocket(protocol)
int openNetlinkSocket(void) {
    base::unique_fd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    if (fd == -1) {
        const int err = errno;
        ALOGE("socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)");
        return -err;
    }

    int rv;

    const int on = 1;
    rv = setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &on, sizeof(on));
    if (rv) ALOGE("setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, %d)", on);

    // this is needed to get sane strace netlink parsing, it allocates the pid
    rv = bind(fd, (const struct sockaddr*)&KERNEL_NLADDR, sizeof(KERNEL_NLADDR));
    if (rv) {
        const int err = errno;
        ALOGE("bind(fd, {AF_NETLINK, 0, 0})");
        return -err;
    }

    // we do not want to receive messages from anyone besides the kernel
    rv = connect(fd, (const struct sockaddr*)&KERNEL_NLADDR, sizeof(KERNEL_NLADDR));
    if (rv) {
        const int err = errno;
        ALOGE("connect(fd, {AF_NETLINK, 0, 0})");
        return -err;
    }

    return fd.release();
}

// TODO: merge with //system/netd/server/SockDiag.cpp:checkError(fd)
int processNetlinkResponse(int fd) {
    struct {
        nlmsghdr h;
        nlmsgerr e;
        char buf[256];
    } resp = {};

    const int rv = recv(fd, &resp, sizeof(resp), MSG_TRUNC);

    if (rv == -1) {
        const int err = errno;
        ALOGE("recv() failed");
        return -err;
    }

    if (rv < (int)NLMSG_SPACE(sizeof(struct nlmsgerr))) {
        ALOGE("recv() returned short packet: %d", rv);
        return -EMSGSIZE;
    }

    if (resp.h.nlmsg_len != (unsigned)rv) {
        ALOGE("recv() returned invalid header length: %d != %d", resp.h.nlmsg_len, rv);
        return -EBADMSG;
    }

    if (resp.h.nlmsg_type != NLMSG_ERROR) {
        ALOGE("recv() did not return NLMSG_ERROR message: %d", resp.h.nlmsg_type);
        return -EBADMSG;
    }

    return resp.e.error;  // returns 0 on success
}

}  // namespace net
}  // namespace android
