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
#include <netdutils/StatusOr.h>

#include "TetherController.h"
#include "IptablesBaseTest.h"

using android::base::Join;
using android::base::StringPrintf;
using android::netdutils::StatusOr;
using TetherStats = android::net::TetherController::TetherStats;
using TetherStatsList = android::net::TetherController::TetherStatsList;

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
                ":tetherctrl_FORWARD -\n"
                "-A tetherctrl_FORWARD -j DROP\n"
                "COMMIT\n"
                "*nat\n"
                ":tetherctrl_nat_POSTROUTING -\n"
                "COMMIT\n" },
        { V6,   "*filter\n"
                ":tetherctrl_FORWARD -\n"
                "COMMIT\n"
                "*raw\n"
                ":tetherctrl_raw_PREROUTING -\n"
                "COMMIT\n" },
    };

    const ExpectedIptablesCommands SETUP_COMMANDS = {
        { V4,   "*filter\n"
                ":tetherctrl_FORWARD -\n"
                "-A tetherctrl_FORWARD -j DROP\n"
                "COMMIT\n"
                "*nat\n"
                ":tetherctrl_nat_POSTROUTING -\n"
                "COMMIT\n" },
        { V6,   "*filter\n"
                ":tetherctrl_FORWARD -\n"
                "COMMIT\n"
                "*raw\n"
                ":tetherctrl_raw_PREROUTING -\n"
                "COMMIT\n" },
        { V4,   "*mangle\n"
                "-A tetherctrl_mangle_FORWARD -p tcp --tcp-flags SYN SYN "
                    "-j TCPMSS --clamp-mss-to-pmtu\n"
                "COMMIT\n" },
        { V4V6, "*filter\n"
                ":tetherctrl_counters -\n"
                "COMMIT\n" },
    };

    ExpectedIptablesCommands firstNatCommands(const char *extIf) {
        std::string v4Cmd = StringPrintf(
            "*nat\n"
            "-A tetherctrl_nat_POSTROUTING -o %s -j MASQUERADE\n"
            "COMMIT\n", extIf);
        std::string v6Cmd =
            "*filter\n"
            "-A tetherctrl_FORWARD -g tetherctrl_counters\n"
            "COMMIT\n";
        return {
            { V4, v4Cmd },
            { V6, v6Cmd },
        };
    }

    ExpectedIptablesCommands startNatCommands(const char *intIf, const char *extIf) {
        std::string rpfilterCmd = StringPrintf(
            "*raw\n"
            "-A tetherctrl_raw_PREROUTING -i %s -m rpfilter --invert ! -s fe80::/64 -j DROP\n"
            "COMMIT\n", intIf);

        std::vector<std::string> v4Cmds = {
            "*filter",
            StringPrintf("-A tetherctrl_FORWARD -i %s -o %s -m state --state"
                         " ESTABLISHED,RELATED -g tetherctrl_counters", extIf, intIf),
            StringPrintf("-A tetherctrl_FORWARD -i %s -o %s -m state --state INVALID -j DROP",
                         intIf, extIf),
            StringPrintf("-A tetherctrl_FORWARD -i %s -o %s -g tetherctrl_counters",
                         intIf, extIf),
            StringPrintf("-A tetherctrl_counters -i %s -o %s -j RETURN", intIf, extIf),
            StringPrintf("-A tetherctrl_counters -i %s -o %s -j RETURN", extIf, intIf),
            "-D tetherctrl_FORWARD -j DROP",
            "-A tetherctrl_FORWARD -j DROP",
            "COMMIT\n",
        };

        std::vector<std::string> v6Cmds = {
            "*filter",
            StringPrintf("-A tetherctrl_counters -i %s -o %s -j RETURN", intIf, extIf),
            StringPrintf("-A tetherctrl_counters -i %s -o %s -j RETURN", extIf, intIf),
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
            "-D tetherctrl_raw_PREROUTING -i %s -m rpfilter --invert ! -s fe80::/64 -j DROP\n"
            "COMMIT\n", intIf);

        std::vector<std::string> v4Cmds = {
            "*filter",
            StringPrintf("-D tetherctrl_FORWARD -i %s -o %s -m state --state"
                         " ESTABLISHED,RELATED -g tetherctrl_counters", extIf, intIf),
            StringPrintf("-D tetherctrl_FORWARD -i %s -o %s -m state --state INVALID -j DROP",
                         intIf, extIf),
            StringPrintf("-D tetherctrl_FORWARD -i %s -o %s -g tetherctrl_counters",
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
    "Chain tetherctrl_counters (4 references)",
    "    pkts      bytes target     prot opt in     out     source               destination",
}, '\n');

std::string kIPv4TetherCounters = Join(std::vector<std::string> {
    "Chain tetherctrl_counters (4 references)",
    "    pkts      bytes target     prot opt in     out     source               destination",
    "      26     2373 RETURN     all  --  wlan0  rmnet0  0.0.0.0/0            0.0.0.0/0",
    "      27     2002 RETURN     all  --  rmnet0 wlan0   0.0.0.0/0            0.0.0.0/0",
    "    1040   107471 RETURN     all  --  bt-pan rmnet0  0.0.0.0/0            0.0.0.0/0",
    "    1450  1708806 RETURN     all  --  rmnet0 bt-pan  0.0.0.0/0            0.0.0.0/0",
}, '\n');

std::string kIPv6TetherCounters = Join(std::vector<std::string> {
    "Chain tetherctrl_counters (2 references)",
    "    pkts      bytes target     prot opt in     out     source               destination",
    "   10000 10000000 RETURN     all      wlan0  rmnet0  ::/0                 ::/0",
    "   20000 20000000 RETURN     all      rmnet0 wlan0   ::/0                 ::/0",
}, '\n');

void expectTetherStatsEqual(const TetherController::TetherStats& expected,
                            const TetherController::TetherStats& actual) {
    EXPECT_EQ(expected.intIface, actual.intIface);
    EXPECT_EQ(expected.extIface, actual.extIface);
    EXPECT_EQ(expected.rxBytes, actual.rxBytes);
    EXPECT_EQ(expected.txBytes, actual.txBytes);
    EXPECT_EQ(expected.rxPackets, actual.rxPackets);
    EXPECT_EQ(expected.txPackets, actual.txPackets);
}

TEST_F(TetherControllerTest, TestGetTetherStats) {
    // Finding no headers is an error.
    ASSERT_FALSE(isOk(mTetherCtrl.getTetherStats()));
    clearIptablesRestoreOutput();

    // Finding only v4 or only v6 headers is an error.
    addIptablesRestoreOutput(kTetherCounterHeaders, "");
    ASSERT_FALSE(isOk(mTetherCtrl.getTetherStats()));
    clearIptablesRestoreOutput();

    addIptablesRestoreOutput("", kTetherCounterHeaders);
    ASSERT_FALSE(isOk(mTetherCtrl.getTetherStats()));
    clearIptablesRestoreOutput();

    // Finding headers but no stats is not an error.
    addIptablesRestoreOutput(kTetherCounterHeaders, kTetherCounterHeaders);
    StatusOr<TetherStatsList> result = mTetherCtrl.getTetherStats();
    ASSERT_TRUE(isOk(result));
    TetherStatsList actual = result.value();
    ASSERT_EQ(0U, actual.size());
    clearIptablesRestoreOutput();


    addIptablesRestoreOutput(kIPv6TetherCounters);
    ASSERT_FALSE(isOk(mTetherCtrl.getTetherStats()));
    clearIptablesRestoreOutput();

    // IPv4 and IPv6 counters are properly added together.
    addIptablesRestoreOutput(kIPv4TetherCounters, kIPv6TetherCounters);
    TetherStats expected0("wlan0", "rmnet0", 20002002, 20027, 10002373, 10026);
    TetherStats expected1("bt-pan", "rmnet0", 1708806, 1450, 107471, 1040);
    result = mTetherCtrl.getTetherStats();
    ASSERT_TRUE(isOk(result));
    actual = result.value();
    ASSERT_EQ(2U, actual.size());
    expectTetherStatsEqual(expected0, result.value()[0]);
    expectTetherStatsEqual(expected1, result.value()[1]);
    clearIptablesRestoreOutput();

    // No stats: error.
    addIptablesRestoreOutput("", kIPv6TetherCounters);
    ASSERT_FALSE(isOk(mTetherCtrl.getTetherStats()));
    clearIptablesRestoreOutput();

    addIptablesRestoreOutput(kIPv4TetherCounters, "");
    ASSERT_FALSE(isOk(mTetherCtrl.getTetherStats()));
    clearIptablesRestoreOutput();

    // Include only one pair of interfaces and things are fine.
    std::vector<std::string> counterLines = android::base::Split(kIPv4TetherCounters, "\n");
    std::vector<std::string> brokenCounterLines = counterLines;
    counterLines.resize(4);
    std::string counters = Join(counterLines, "\n") + "\n";
    addIptablesRestoreOutput(counters, counters);
    TetherStats expected1_0("wlan0", "rmnet0", 4004, 54, 4746, 52);
    result = mTetherCtrl.getTetherStats();
    ASSERT_TRUE(isOk(result));
    actual = result.value();
    ASSERT_EQ(1U, actual.size());
    expectTetherStatsEqual(expected1_0, actual[0]);
    clearIptablesRestoreOutput();

    // But if interfaces aren't paired, it's always an error.
    counterLines.resize(3);
    counters = Join(counterLines, "\n") + "\n";
    addIptablesRestoreOutput(counters, counters);
    result = mTetherCtrl.getTetherStats();
    ASSERT_FALSE(isOk(result));
    clearIptablesRestoreOutput();

    // Token unit test of the fact that we return the stats in the error message which the caller
    // ignores.
    std::string expectedError = counters;
    std::string err = result.status().msg();
    ASSERT_LE(expectedError.size(), err.size());
    EXPECT_TRUE(std::equal(expectedError.rbegin(), expectedError.rend(), err.rbegin()));
}

}  // namespace net
}  // namespace android
