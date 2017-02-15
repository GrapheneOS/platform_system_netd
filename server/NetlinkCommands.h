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

#ifndef NETD_SERVER_NETLINK_UTIL_H
#define NETD_SERVER_NETLINK_UTIL_H

#include <functional>

#include "NetdConstants.h"

namespace android {
namespace net {

const sockaddr_nl KERNEL_NLADDR = {AF_NETLINK, 0, 0, 0};

// Generic code for processing netlink dumps.
const int kNetlinkDumpBufferSize = 8192;
typedef std::function<void(nlmsghdr *)> NetlinkDumpCallback;

// Opens an RTNetlink socket and connects it to the kernel.
WARN_UNUSED_RESULT int openRtNetlinkSocket();

// Receives a netlink ACK. Returns 0 if the command succeeded or negative errno if the command
// failed or receiving the ACK failed.
WARN_UNUSED_RESULT int recvNetlinkAck(int sock);

// Sends a netlink request and possibly expects an ACK. The first element of iov should be null and
// will be set to the netlink message headerheader. The subsequent elements are the contents of the
// request.
WARN_UNUSED_RESULT int sendNetlinkRequest(uint16_t action, uint16_t flags, iovec* iov, int iovlen);

// Disable optimizations in ASan build.
// ASan reports an out-of-bounds 32-bit(!) access in the first loop of the
// function (over iov[]).
#ifdef __clang__
#if __has_feature(address_sanitizer)
__attribute__((optnone))
#endif
#endif
WARN_UNUSED_RESULT int sendNetlinkRequest(uint16_t action, uint16_t flags, iovec* iov, int iovlen,
                                          const NetlinkDumpCallback& callback);

// Processes a netlink dump, passing every message to the specified |callback|.
WARN_UNUSED_RESULT int processNetlinkDump(int sock, const NetlinkDumpCallback& callback);

}  // namespace net
}  // namespace android

#endif  // NETD_SERVER_NETLINK_UTIL_H
