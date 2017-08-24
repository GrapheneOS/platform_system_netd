/*
 * Copyright 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * TetherControllerTest.cpp - unit tests for TetherController.cpp
 */

#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <gtest/gtest.h>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "TetherController.h"
#include "IptablesBaseTest.h"

using android::base::Join;
using android::base::StringPrintf;

namespace android {
namespace net {

class TetherControllerTest : public IptablesBaseTest {
public:
    TetherControllerTest() {
        TetherController::iptablesRestoreFunction = fakeExecIptablesRestoreWithOutput;
    }

protected:
    TetherController mTetherCtrl;

    int setDefaults() {
        return mTetherCtrl.setDefaults();
    }

    const ExpectedIptablesCommands FLUSH_COMMANDS = {
        { V4,   "*filter\n"
                ":natctrl_FORWARD -\n"
                "-A natctrl_FORWARD -j DROP\n"
                "COMMIT\n"
                "*nat\n"
                ":natctrl_nat_POSTROUTING -\n"
                "COMMIT\n" },
        { V6,   "*filter\n"
                ":natctrl_FORWARD -\n"
                "COMMIT\n"
                "*raw\n"
                ":natctrl_raw_PREROUTING -\n"
                "COMMIT\n" },
    };

    const ExpectedIptablesCommands SETUP_COMMANDS = {
        { V4,   "*filter\n"
                ":natctrl_FORWARD -\n"
                "-A natctrl_FORWARD -j DROP\n"
                "COMMIT\n"
                "*nat\n"
                ":natctrl_nat_POSTROUTING -\n"
                "COMMIT\n" },
        { V6,   "*filter\n"
                ":natctrl_FORWARD -\n"
                "COMMIT\n"
                "*raw\n"
                ":natctrl_raw_PREROUTING -\n"
                "COMMIT\n" },
        { V4,   "*mangle\n"
                "-A natctrl_mangle_FORWARD -p tcp --tcp-flags SYN SYN "
                    "-j TCPMSS --clamp-mss-to-pmtu\n"
                "COMMIT\n" },
        { V4V6, "*filter\n"
                ":natctrl_tether_counters -\n"
                "COMMIT\n" },
    };

    ExpectedIptablesCommands firstNatCommands(const char *extIf) {
        std::string v4Cmd = StringPrintf(
            "*nat\n"
            "-A natctrl_nat_POSTROUTING -o %s -j MASQUERADE\n"
            "COMMIT\n", extIf);
        std::string v6Cmd =
            "*filter\n"
            "-A natctrl_FORWARD -g natctrl_tether_counters\n"
            "COMMIT\n";
        return {
            { V4, v4Cmd },
            { V6, v6Cmd },
        };
    }

    ExpectedIptablesCommands startNatCommands(const char *intIf, const char *extIf) {
        std::string rpfilterCmd = StringPrintf(
            "*raw\n"
            "-A natctrl_raw_PREROUTING -i %s -m rpfilter --invert ! -s fe80::/64 -j DROP\n"
            "COMMIT\n", intIf);

        std::vector<std::string> v4Cmds = {
            "*filter",
            StringPrintf("-A natctrl_FORWARD -i %s -o %s -m state --state"
                         " ESTABLISHED,RELATED -g natctrl_tether_counters", extIf, intIf),
            StringPrintf("-A natctrl_FORWARD -i %s -o %s -m state --state INVALID -j DROP",
                         intIf, extIf),
            StringPrintf("-A natctrl_FORWARD -i %s -o %s -g natctrl_tether_counters",
                         intIf, extIf),
            StringPrintf("-A natctrl_tether_counters -i %s -o %s -j RETURN", intIf, extIf),
            StringPrintf("-A natctrl_tether_counters -i %s -o %s -j RETURN", extIf, intIf),
            "-D natctrl_FORWARD -j DROP",
            "-A natctrl_FORWARD -j DROP",
            "COMMIT\n",
        };

        std::vector<std::string> v6Cmds = {
            "*filter",
            StringPrintf("-A natctrl_tether_counters -i %s -o %s -j RETURN", intIf, extIf),
            StringPrintf("-A natctrl_tether_counters -i %s -o %s -j RETURN", extIf, intIf),
            "COMMIT\n",
        };

        return {
            { V6, rpfilterCmd },
            { V4, Join(v4Cmds, '\n') },
            { V6, Join(v6Cmds, '\n') },
        };
    }

    ExpectedIptablesCommands stopNatCommands(const char *intIf, const char *extIf) {
        std::string rpfilterCmd = StringPrintf(
            "*raw\n"
            "-D natctrl_raw_PREROUTING -i %s -m rpfilter --invert ! -s fe80::/64 -j DROP\n"
            "COMMIT\n", intIf);

        std::vector<std::string> v4Cmds = {
            "*filter",
            StringPrintf("-D natctrl_FORWARD -i %s -o %s -m state --state"
                         " ESTABLISHED,RELATED -g natctrl_tether_counters", extIf, intIf),
            StringPrintf("-D natctrl_FORWARD -i %s -o %s -m state --state INVALID -j DROP",
                         intIf, extIf),
            StringPrintf("-D natctrl_FORWARD -i %s -o %s -g natctrl_tether_counters",
                         intIf, extIf),
            "COMMIT\n",
        };

        return {
            { V6, rpfilterCmd },
            { V4, Join(v4Cmds, '\n') },
        };

    }
};

TEST_F(TetherControllerTest, TestSetupIptablesHooks) {
    mTetherCtrl.setupIptablesHooks();
    expectIptablesRestoreCommands(SETUP_COMMANDS);
}

TEST_F(TetherControllerTest, TestSetDefaults) {
    setDefaults();
    expectIptablesRestoreCommands(FLUSH_COMMANDS);
}

TEST_F(TetherControllerTest, TestAddAndRemoveNat) {
    ExpectedIptablesCommands expected;
    ExpectedIptablesCommands setupFirstNatCommands = firstNatCommands("rmnet0");
    ExpectedIptablesCommands startFirstNatCommands = startNatCommands("wlan0", "rmnet0");
    expected.insert(expected.end(), setupFirstNatCommands.begin(), setupFirstNatCommands.end());
    expected.insert(expected.end(), startFirstNatCommands.begin(), startFirstNatCommands.end());
    mTetherCtrl.enableNat("wlan0", "rmnet0");
    expectIptablesRestoreCommands(expected);

    ExpectedIptablesCommands startOtherNat = startNatCommands("usb0", "rmnet0");
    mTetherCtrl.enableNat("usb0", "rmnet0");
    expectIptablesRestoreCommands(startOtherNat);

    ExpectedIptablesCommands stopOtherNat = stopNatCommands("wlan0", "rmnet0");
    mTetherCtrl.disableNat("wlan0", "rmnet0");
    expectIptablesRestoreCommands(stopOtherNat);

    expected = stopNatCommands("usb0", "rmnet0");
    expected.insert(expected.end(), FLUSH_COMMANDS.begin(), FLUSH_COMMANDS.end());
    mTetherCtrl.disableNat("usb0", "rmnet0");
    expectIptablesRestoreCommands(expected);
}

std::string kTetherCounterHeaders = Join(std::vector<std::string> {
    "Chain natctrl_tether_counters (4 references)",
    "    pkts      bytes target     prot opt in     out     source               destination",
}, '\n');

std::string kIPv4TetherCounters = Join(std::vector<std::string> {
    "Chain natctrl_tether_counters (4 references)",
    "    pkts      bytes target     prot opt in     out     source               destination",
    "      26     2373 RETURN     all  --  wlan0  rmnet0  0.0.0.0/0            0.0.0.0/0",
    "      27     2002 RETURN     all  --  rmnet0 wlan0   0.0.0.0/0            0.0.0.0/0",
    "    1040   107471 RETURN     all  --  bt-pan rmnet0  0.0.0.0/0            0.0.0.0/0",
    "    1450  1708806 RETURN     all  --  rmnet0 bt-pan  0.0.0.0/0            0.0.0.0/0",
}, '\n');

std::string kIPv6TetherCounters = Join(std::vector<std::string> {
    "Chain natctrl_tether_counters (2 references)",
    "    pkts      bytes target     prot opt in     out     source               destination",
    "   10000 10000000 RETURN     all      wlan0  rmnet0  ::/0                 ::/0",
    "   20000 20000000 RETURN     all      rmnet0 wlan0   ::/0                 ::/0",
}, '\n');

std::string readSocketClientResponse(int fd) {
    char buf[32768];
    ssize_t bytesRead = read(fd, buf, sizeof(buf));
    if (bytesRead < 0) {
        return "";
    }
    for (int i = 0; i < bytesRead; i++) {
        if (buf[i] == '\0') buf[i] = '\n';
    }
    return std::string(buf, bytesRead);
}

void expectNoSocketClientResponse(int fd) {
    char buf[64];
    EXPECT_EQ(-1, read(fd, buf, sizeof(buf))) << "Unexpected response: " << buf << "\n";
}

TEST_F(TetherControllerTest, TestGetTetherStats) {
    int socketPair[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, socketPair));
    ASSERT_EQ(0, fcntl(socketPair[0], F_SETFL, O_NONBLOCK | fcntl(socketPair[0], F_GETFL)));
    ASSERT_EQ(0, fcntl(socketPair[1], F_SETFL, O_NONBLOCK | fcntl(socketPair[1], F_GETFL)));
    SocketClient cli(socketPair[0], false);

    std::string err;

    // If no filter is specified, both IPv4 and IPv6 counters must have at least one interface pair.
    addIptablesRestoreOutput(kIPv4TetherCounters);
    ASSERT_EQ(-1, mTetherCtrl.getTetherStats(&cli, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearIptablesRestoreOutput();

    addIptablesRestoreOutput(kIPv6TetherCounters);
    ASSERT_EQ(-1, mTetherCtrl.getTetherStats(&cli, err));
    clearIptablesRestoreOutput();

    // IPv4 and IPv6 counters are properly added together.
    addIptablesRestoreOutput(kIPv4TetherCounters, kIPv6TetherCounters);
    std::string expected =
            "114 wlan0 rmnet0 10002373 10026 20002002 20027\n"
            "114 bt-pan rmnet0 107471 1040 1708806 1450\n"
            "200 Tethering stats list completed\n";
    ASSERT_EQ(0, mTetherCtrl.getTetherStats(&cli, err));
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));
    expectNoSocketClientResponse(socketPair[1]);
    clearIptablesRestoreOutput();

    // No stats: error.
    addIptablesRestoreOutput("", kIPv6TetherCounters);
    ASSERT_EQ(-1, mTetherCtrl.getTetherStats(&cli, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearIptablesRestoreOutput();

    addIptablesRestoreOutput(kIPv4TetherCounters, "");
    ASSERT_EQ(-1, mTetherCtrl.getTetherStats(&cli, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearIptablesRestoreOutput();

    // Include only one pair of interfaces and things are fine.
    std::vector<std::string> counterLines = android::base::Split(kIPv4TetherCounters, "\n");
    std::vector<std::string> brokenCounterLines = counterLines;
    counterLines.resize(4);
    std::string counters = Join(counterLines, "\n") + "\n";
    addIptablesRestoreOutput(counters, counters);
    expected =
            "114 wlan0 rmnet0 4746 52 4004 54\n"
            "200 Tethering stats list completed\n";
    ASSERT_EQ(0, mTetherCtrl.getTetherStats(&cli, err));
    ASSERT_EQ(expected, readSocketClientResponse(socketPair[1]));
    clearIptablesRestoreOutput();

    // But if interfaces aren't paired, it's always an error.
    err = "";
    counterLines.resize(3);
    counters = Join(counterLines, "\n") + "\n";
    addIptablesRestoreOutput(counters, counters);
    ASSERT_EQ(-1, mTetherCtrl.getTetherStats(&cli, err));
    expectNoSocketClientResponse(socketPair[1]);
    clearIptablesRestoreOutput();

    // Token unit test of the fact that we return the stats in the error message which the caller
    // ignores.
    std::string expectedError = counters;
    EXPECT_EQ(expectedError, err);
}

}  // namespace net
}  // namespace android
