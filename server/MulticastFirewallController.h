#ifndef _MULTICAST_FIREWALL_CONTROLLER_H
#define _MULTICAST_FIREWALL_CONTROLLER_H

#include <sys/types.h>
#include <set>
#include <string>
#include <vector>

#include "NetdConstants.h"

namespace android {
namespace net {

/*
 * Firewall that DROPS all multicast, IGMP and MLD going in/out VPN (tun) interfaces. The main
 * purpose of this firewall is to prevent users from sending/receiving multicast traffic over the
 * tun interfaces of other users, as that would be a violation of the requirement that VPNs are
 * profile isolated.
 */
class MulticastFirewallController {
public:
  MulticastFirewallController();

  int setupIptablesHooks(void);

  static const char* TABLE;

  static const char* LOCAL_INPUT;
  static const char* LOCAL_OUTPUT;
  static const char* LOCAL_FORWARD;

protected:
  friend class MulticastFirewallControllerTest;
  static int (*execIptablesRestore)(IptablesTarget target, const std::string& commands);

private:
  std::set<std::string> mIfaceRules;
  int flushRules(void);

  static const char* MULTICAST_RANGE_IPV4;
  static const char* MULTICAST_RANGE_IPV6;

  static const int MC_LISTENER_QUERY;
  static const int MLDV1_MC_LISTENER_REPORT;
  static const int MLDV2_MC_LISTENER_REPORT;
  static const int MC_LISTENER_DONE;

  static const int IGMP_PROTOCOL_NUMBER;

  static const char* VPN_INTERFACE_NAME;
};

}  // namespace net
}  // namespace android

#endif
