#include <set>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint>

#define LOG_TAG "MulticastFirewallController"
#define LOG_NDEBUG 0

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <log/log.h>

#include "Controllers.h"
#include "MulticastFirewallController.h"
#include "NetdConstants.h"

using android::base::Join;
using android::base::StringAppendF;
using android::base::StringPrintf;

namespace android {
namespace net {

auto MulticastFirewallController::execIptablesRestore = ::execIptablesRestore;

const char* MulticastFirewallController::TABLE = "filter";

const char* MulticastFirewallController::LOCAL_INPUT = "mfw_INPUT";
const char* MulticastFirewallController::LOCAL_FORWARD = "mfw_FORWARD";
const char* MulticastFirewallController::LOCAL_OUTPUT = "mfw_OUTPUT";

const char* MulticastFirewallController::MULTICAST_RANGE_IPV4 = "224.0.0.0/4";
const char* MulticastFirewallController::MULTICAST_RANGE_IPV6 = "ff00::/8";

// RFC2710. Need to manually specify these as the iptables typenames are lacking.
const int MulticastFirewallController::MC_LISTENER_QUERY = 130;
const int MulticastFirewallController::MLDV1_MC_LISTENER_REPORT = 131;
const int MulticastFirewallController::MLDV2_MC_LISTENER_REPORT = 143;
const int MulticastFirewallController::MC_LISTENER_DONE = 132;

const int MulticastFirewallController::IGMP_PROTOCOL_NUMBER = 2;

const char* MulticastFirewallController::VPN_INTERFACE_NAME = "tun+";

MulticastFirewallController::MulticastFirewallController(void) {
    mIfaceRules = {};
}

int MulticastFirewallController::setupIptablesHooks(void) {
    return flushRules();
}

int MulticastFirewallController::flushRules() {
    // All this firewall is doing is dropping multicast, IGMP and MLD over tun interfaces in all
    // chains. There is overlap between these rules and some of the general upstream eBPF filtering,
    // especially for INPUT. However, we don't trust that filtering. It's not good that we have
    // special handling for multicast in FORWARD, as this should be handled generally. We will look
    // to do this in future as we continue to improve upstream's networking.
    // The reason to drop IGMP/MLD in the INPUT chain even though it will never reach apps is
    // because it has the potential to impact the multicast routing tables which all apps can
    // access. In general, all protocols which can be used to modify the networking environment
    // should not be allowed in from the VPN interfaces as this is a cross-user side channel. Of
    // course these protocols coming in on the physical interfaces can also be a side channel, but
    // can't do anything about that. Need to find a way to move to network namespaces and eliminate
    // the issue entirely. This firewall is a tiny band-aid on a huge gash.
    std::string command = Join(std::vector<std::string> {
            "*filter",
            ":mfw_INPUT -",
            ":mfw_FORWARD -",
            ":mfw_OUTPUT -",
            // Have to match on dest addr instead of using -m addrtype --dst-type MULTICAST because
            // missing kernel module for it.
            StringPrintf("-4 -A mfw_INPUT -i %s -d %s -j DROP", VPN_INTERFACE_NAME,
                         MULTICAST_RANGE_IPV4),
            // IGMP/MLD packets can have a unicast destination address in some rare cases, so drop
            // it explicitly instead of relying on it having a multicast daddr.
            StringPrintf("-4 -A mfw_INPUT -i %s -p %d -j DROP", VPN_INTERFACE_NAME,
                         IGMP_PROTOCOL_NUMBER),
            StringPrintf("-4 -A mfw_FORWARD -d %s -j DROP", MULTICAST_RANGE_IPV4),
            StringPrintf("-4 -A mfw_FORWARD -p %d -j DROP", IGMP_PROTOCOL_NUMBER),
            StringPrintf("-4 -A mfw_OUTPUT -o %s -d %s -j DROP", VPN_INTERFACE_NAME,
                         MULTICAST_RANGE_IPV4),
            StringPrintf("-4 -A mfw_OUTPUT -o %s -p %d -j DROP", VPN_INTERFACE_NAME,
                         IGMP_PROTOCOL_NUMBER),
            StringPrintf("-6 -A mfw_INPUT -i %s -d %s -j DROP", VPN_INTERFACE_NAME,
                         MULTICAST_RANGE_IPV6),
            StringPrintf("-6 -A mfw_INPUT -i %s -p icmpv6 --icmpv6-type %d -j DROP",
                         VPN_INTERFACE_NAME, MC_LISTENER_QUERY),
            StringPrintf("-6 -A mfw_INPUT -i %s -p icmpv6 --icmpv6-type %d -j DROP",
                         VPN_INTERFACE_NAME, MLDV1_MC_LISTENER_REPORT),
            StringPrintf("-6 -A mfw_INPUT -i %s -p icmpv6 --icmpv6-type %d -j DROP",
                         VPN_INTERFACE_NAME, MLDV2_MC_LISTENER_REPORT),
            StringPrintf("-6 -A mfw_INPUT -i %s -p icmpv6 --icmpv6-type %d -j DROP",
                         VPN_INTERFACE_NAME, MC_LISTENER_DONE),
            StringPrintf("-6 -A mfw_FORWARD -d %s -j DROP", MULTICAST_RANGE_IPV6),
            StringPrintf("-6 -A mfw_FORWARD -p icmpv6 --icmpv6-type %d -j DROP",
                         MC_LISTENER_QUERY),
            StringPrintf("-6 -A mfw_FORWARD -p icmpv6 --icmpv6-type %d -j DROP",
                         MLDV1_MC_LISTENER_REPORT),
            StringPrintf("-6 -A mfw_FORWARD -p icmpv6 --icmpv6-type %d -j DROP",
                         MLDV2_MC_LISTENER_REPORT),
            StringPrintf("-6 -A mfw_FORWARD -p icmpv6 --icmpv6-type %d -j DROP",
                         MC_LISTENER_DONE),
            // This is to keep compatibility with DDG. When an IPv6 address is assigned to a NIC,
            // the kernel automatically generates multicast listener report and router
            // solicitation packets. In most configurations these packets don't serve any meaningful
            // purpose and can safely be dropped. For some reason DDG panics unless at least one of
            // these packets goes out over the tun NIC. We can't allow listener reports as apps can
            // generate them across users, but router advertisements can only be generated by
            // VPN apps over the tun interface that they create themselves.
            StringPrintf("-6 -A mfw_OUTPUT -o %s -p icmpv6 --icmpv6-type router-solicitation "
                         "-j RETURN", VPN_INTERFACE_NAME),
            StringPrintf("-6 -A mfw_OUTPUT -o %s -d %s -j DROP", VPN_INTERFACE_NAME,
                         MULTICAST_RANGE_IPV6),
            StringPrintf("-6 -A mfw_OUTPUT -o %s -p icmpv6 --icmpv6-type %d -j DROP",
                         VPN_INTERFACE_NAME, MC_LISTENER_QUERY),
            StringPrintf("-6 -A mfw_OUTPUT -o %s -p icmpv6 --icmpv6-type %d -j DROP",
                         VPN_INTERFACE_NAME, MLDV1_MC_LISTENER_REPORT),
            StringPrintf("-6 -A mfw_OUTPUT -o %s -p icmpv6 --icmpv6-type %d -j DROP",
                         VPN_INTERFACE_NAME, MLDV2_MC_LISTENER_REPORT),
            StringPrintf("-6 -A mfw_OUTPUT -o %s -p icmpv6 --icmpv6-type %d -j DROP",
                         VPN_INTERFACE_NAME, MC_LISTENER_DONE),
           "COMMIT\n"
    }, "\n");

    return (execIptablesRestore(V4V6, command.c_str()) == 0) ? 0 : -EREMOTEIO;
}

}  // namespace net
}  // namespace android
