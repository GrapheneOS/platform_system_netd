/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "ClatdController.h"

#include <map>
#include <string>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_TAG "ClatdController"
#include <log/log.h>

#include "android-base/unique_fd.h"

extern "C" {
#include "netutils/checksum.h"
}

#include "Fwmark.h"
#include "NetdConstants.h"
#include "NetworkController.h"
#include "netid_client.h"

static const char* kClatdPath = "/system/bin/clatd";

// For historical reasons, start with 192.0.0.4, and after that, use all subsequent addresses in
// 192.0.0.0/29 (RFC 7335).
static const char* kV4AddrString = "192.0.0.4";
static const in_addr kV4Addr = {inet_addr(kV4AddrString)};
static const int kV4AddrLen = 29;

using android::base::unique_fd;

namespace android {
namespace net {

ClatdController::ClatdController(NetworkController* controller)
        : mNetCtrl(controller) {
}

ClatdController::~ClatdController() {
}

bool ClatdController::isIpv4AddressFree(in_addr_t addr) {
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s == -1) {
        return 0;
    }

    // Attempt to connect to the address. If the connection succeeds and getsockname returns the
    // same then the address is already assigned to the system and we can't use it.
    struct sockaddr_in sin = {.sin_family = AF_INET, .sin_addr = {addr}, .sin_port = 53};
    socklen_t len = sizeof(sin);
    bool inuse = connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0 &&
                 getsockname(s, (struct sockaddr*)&sin, &len) == 0 && (size_t)len >= sizeof(sin) &&
                 sin.sin_addr.s_addr == addr;

    close(s);
    return !inuse;
}

// Picks a free IPv4 address, starting from ip and trying all addresses in the prefix in order.
//   ip        - the IP address from the configuration file
//   prefixlen - the length of the prefix from which addresses may be selected.
//   returns: the IPv4 address, or INADDR_NONE if no addresses were available
in_addr_t ClatdController::selectIpv4Address(const in_addr ip, int16_t prefixlen) {
    // Don't accept prefixes that are too large because we scan addresses one by one.
    if (prefixlen < 16 || prefixlen > 32) {
        return INADDR_NONE;
    }

    // All these are in host byte order.
    in_addr_t mask = 0xffffffff >> (32 - prefixlen) << (32 - prefixlen);
    in_addr_t ipv4 = ntohl(ip.s_addr);
    in_addr_t first_ipv4 = ipv4;
    in_addr_t prefix = ipv4 & mask;

    // Pick the first IPv4 address in the pool, wrapping around if necessary.
    // So, for example, 192.0.0.4 -> 192.0.0.5 -> 192.0.0.6 -> 192.0.0.7 -> 192.0.0.0.
    do {
        if (isIpv4AddressFreeFunc(htonl(ipv4))) {
            return htonl(ipv4);
        }
        ipv4 = prefix | ((ipv4 + 1) & ~mask);
    } while (ipv4 != first_ipv4);

    return INADDR_NONE;
}

// Alters the bits in the IPv6 address to make them checksum neutral with v4 and nat64Prefix.
void ClatdController::makeChecksumNeutral(in6_addr* v6, const in_addr v4,
                                          const in6_addr& nat64Prefix) {
    // Fill last 8 bytes of IPv6 address with random bits.
    arc4random_buf(&v6->s6_addr[8], 8);

    // Make the IID checksum-neutral. That is, make it so that:
    //   checksum(Local IPv4 | Remote IPv4) = checksum(Local IPv6 | Remote IPv6)
    // in other words (because remote IPv6 = NAT64 prefix | Remote IPv4):
    //   checksum(Local IPv4) = checksum(Local IPv6 | NAT64 prefix)
    // Do this by adjusting the two bytes in the middle of the IID.

    uint16_t middlebytes = (v6->s6_addr[11] << 8) + v6->s6_addr[12];

    uint32_t c1 = ip_checksum_add(0, &v4, sizeof(v4));
    uint32_t c2 = ip_checksum_add(0, &nat64Prefix, sizeof(nat64Prefix)) +
                  ip_checksum_add(0, v6, sizeof(*v6));

    uint16_t delta = ip_checksum_adjust(middlebytes, c1, c2);
    v6->s6_addr[11] = delta >> 8;
    v6->s6_addr[12] = delta & 0xff;
}

// Picks a random interface ID that is checksum neutral with the IPv4 address and the NAT64 prefix.
int ClatdController::generateIpv6Address(const char* iface, const in_addr v4,
                                         const in6_addr& nat64Prefix, in6_addr* v6) {
    unique_fd s(socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (s == -1) return -errno;

    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1) == -1) {
        return -errno;
    }

    sockaddr_in6 sin6 = {.sin6_family = AF_INET6, .sin6_addr = nat64Prefix};
    if (connect(s, reinterpret_cast<struct sockaddr*>(&sin6), sizeof(sin6)) == -1) {
        return -errno;
    }

    socklen_t len = sizeof(sin6);
    if (getsockname(s, reinterpret_cast<struct sockaddr*>(&sin6), &len) == -1) {
        return -errno;
    }

    *v6 = sin6.sin6_addr;

    if (IN6_IS_ADDR_UNSPECIFIED(v6) || IN6_IS_ADDR_LOOPBACK(v6) || IN6_IS_ADDR_LINKLOCAL(v6) ||
        IN6_IS_ADDR_SITELOCAL(v6) || IN6_IS_ADDR_ULA(v6)) {
        return -ENETUNREACH;
    }

    makeChecksumNeutral(v6, v4, nat64Prefix);

    return 0;
}

// Finds the tracker of the clatd running on interface |interface|, or nullptr if clatd has not been
// started  on |interface|.
ClatdController::ClatdTracker* ClatdController::getClatdTracker(const std::string& interface) {
    auto it = mClatdTrackers.find(interface);
    return (it == mClatdTrackers.end() ? nullptr : &it->second);
}

// Initializes a ClatdTracker for the specified interface.
int ClatdController::ClatdTracker::init(const std::string& interface,
                                        const std::string& nat64Prefix) {
    netId = netCtrl->getNetworkForInterface(interface.c_str());
    if (netId == NETID_UNSET) {
        ALOGE("Interface %s not assigned to any netId", interface.c_str());
        errno = ENODEV;
        return -errno;
    }

    fwmark.netId = netId;
    fwmark.explicitlySelected = true;
    fwmark.protectedFromVpn = true;
    fwmark.permission = PERMISSION_SYSTEM;

    snprintf(fwmarkString, sizeof(fwmarkString), "0x%x", fwmark.intValue);
    snprintf(netIdString, sizeof(netIdString), "%u", netId);
    strlcpy(iface, interface.c_str(), sizeof(iface));

    // Pass in everything that clatd needs: interface, a netid to use for DNS lookups, a fwmark for
    // outgoing packets, the NAT64 prefix, and the IPv4 and IPv6 addresses.
    // Validate the prefix and strip off the prefix length.
    uint8_t family;
    uint8_t prefixLen;
    int res = parsePrefix(nat64Prefix.c_str(), &family, &dst, sizeof(dst), &prefixLen);
    // clatd only supports /96 prefixes.
    if (res != sizeof(dst)) return res;
    if (family != AF_INET6) return -EAFNOSUPPORT;
    if (prefixLen != 96) return -EINVAL;
    if (!inet_ntop(AF_INET6, &dst, dstString, sizeof(dstString))) return -errno;

    // Pick an IPv4 address.
    // TODO: this picks the address based on other addresses that are assigned to interfaces, but
    // the address is only actually assigned to an interface once clatd starts up. So we could end
    // up with two clatd instances with the same IPv4 address.
    // Stop doing this and instead pick a free one from the kV4Addr pool.
    in_addr v4 = {selectIpv4Address(kV4Addr, kV4AddrLen)};
    if (v4.s_addr == INADDR_NONE) {
        ALOGE("No free IPv4 address in %s/%d", kV4AddrString, kV4AddrLen);
        return -EADDRNOTAVAIL;
    }
    if (!inet_ntop(AF_INET, &v4, v4Str, sizeof(v4Str))) return -errno;

    // Generate a checksum-neutral IID.
    if (generateIpv6Address(iface, v4, dst, &v6)) {
        ALOGE("Unable to find global source address on %s for %s", iface, dstString);
        return -EADDRNOTAVAIL;
    }
    if (!inet_ntop(AF_INET6, &v6, v6Str, sizeof(v6Str))) return -errno;

    ALOGD("starting clatd on %s v4=%s v6=%s dst=%s", iface, v4Str, v6Str, dstString);
    return 0;
}

int ClatdController::startClatd(const std::string& interface, const std::string& nat64Prefix,
                                std::string* v6Str) {
    ClatdTracker* existing = getClatdTracker(interface);
    if (existing != nullptr) {
        ALOGE("clatd pid=%d already started on %s", existing->pid, interface.c_str());
        errno = EBUSY;
        return -errno;
    }

    ClatdTracker tracker(mNetCtrl);
    if (int ret = tracker.init(interface, nat64Prefix)) {
        return ret;
    }

    std::string progname("clatd-");
    progname += tracker.iface;

    // clang-format off
    char* args[] = {(char*) progname.c_str(),
                    (char*) "-i", tracker.iface,
                    (char*) "-n", tracker.netIdString,
                    (char*) "-m", tracker.fwmarkString,
                    (char*) "-p", tracker.dstString,
                    (char*) "-4", tracker.v4Str,
                    (char*) "-6", tracker.v6Str,
                    nullptr};
    // clang-format on

    // Specify no flags and no actions, posix_spawn will use vfork and is
    // guaranteed to return only once exec has been called.
    int res = posix_spawn(&tracker.pid, kClatdPath, nullptr, nullptr, args, nullptr);
    if (res) {
        ALOGE("posix_spawn failed (%s)", strerror(res));
        return -res;
    }

    mClatdTrackers[interface] = tracker;
    ALOGD("clatd started on %s", interface.c_str());

    *v6Str = tracker.v6Str;
    return 0;
}

int ClatdController::stopClatd(const std::string& interface) {
    ClatdTracker* tracker = getClatdTracker(interface);

    if (tracker == nullptr) {
        ALOGE("clatd already stopped");
        return -ENODEV;
    }

    ALOGD("Stopping clatd pid=%d on %s", tracker->pid, interface.c_str());

    kill(tracker->pid, SIGTERM);
    waitpid(tracker->pid, nullptr, 0);
    mClatdTrackers.erase(interface);

    ALOGD("clatd on %s stopped", interface.c_str());

    return 0;
}

auto ClatdController::isIpv4AddressFreeFunc = isIpv4AddressFree;

}  // namespace net
}  // namespace android
