#include <string>
#include <vector>
#include <stdio.h>

#include <gtest/gtest.h>

#include "MulticastFirewallController.h"
#include "IptablesBaseTest.h"

namespace android {
namespace net {

class MulticastFirewallControllerTest : public IptablesBaseTest {
protected:
    MulticastFirewallControllerTest() {
        MulticastFirewallController::execIptablesRestore = fakeExecIptablesRestore;
    }
    MulticastFirewallController mFw;
};

TEST_F(MulticastFirewallControllerTest, TestFirewall) {
    std::vector<std::string> expectedCommands = {
            "*filter\n"
            ":mfw_INPUT -\n"
            ":mfw_FORWARD -\n"
            ":mfw_OUTPUT -\n"
            "-4 -A mfw_INPUT -i tun+ -d 224.0.0.0/4 -j DROP\n"
            "-4 -A mfw_INPUT -i tun+ -p 2 -j DROP\n"
            "-4 -A mfw_FORWARD -d 224.0.0.0/4 -j DROP\n"
            "-4 -A mfw_FORWARD -p 2 -j DROP\n"
            "-4 -A mfw_OUTPUT -o tun+ -d 224.0.0.0/4 -j DROP\n"
            "-4 -A mfw_OUTPUT -o tun+ -p 2 -j DROP\n"
            "-6 -A mfw_INPUT -i tun+ -d ff00::/8 -j DROP\n"
            "-6 -A mfw_INPUT -i tun+ -p icmpv6 --icmpv6-type 130 -j DROP\n"
            "-6 -A mfw_INPUT -i tun+ -p icmpv6 --icmpv6-type 131 -j DROP\n"
            "-6 -A mfw_INPUT -i tun+ -p icmpv6 --icmpv6-type 143 -j DROP\n"
            "-6 -A mfw_INPUT -i tun+ -p icmpv6 --icmpv6-type 132 -j DROP\n"
            "-6 -A mfw_FORWARD -d ff00::/8 -j DROP\n"
            "-6 -A mfw_FORWARD -p icmpv6 --icmpv6-type 130 -j DROP\n"
            "-6 -A mfw_FORWARD -p icmpv6 --icmpv6-type 131 -j DROP\n"
            "-6 -A mfw_FORWARD -p icmpv6 --icmpv6-type 143 -j DROP\n"
            "-6 -A mfw_FORWARD -p icmpv6 --icmpv6-type 132 -j DROP\n"
            "-6 -A mfw_OUTPUT -o tun+ -p icmpv6 --icmpv6-type router-solicitation -j RETURN\n"
            "-6 -A mfw_OUTPUT -o tun+ -d ff00::/8 -j DROP\n"
            "-6 -A mfw_OUTPUT -o tun+ -p icmpv6 --icmpv6-type 130 -j DROP\n"
            "-6 -A mfw_OUTPUT -o tun+ -p icmpv6 --icmpv6-type 131 -j DROP\n"
            "-6 -A mfw_OUTPUT -o tun+ -p icmpv6 --icmpv6-type 143 -j DROP\n"
            "-6 -A mfw_OUTPUT -o tun+ -p icmpv6 --icmpv6-type 132 -j DROP\n"
            "COMMIT\n"};

    EXPECT_EQ(0, mFw.setupIptablesHooks());
    expectIptablesRestoreCommands(expectedCommands);
}

}  // namespace net
}  // namespace android
