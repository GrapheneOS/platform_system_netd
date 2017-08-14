/*
 * Copyright 2017 The Android Open Source Project
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
 * ControllersTest.cpp - unit tests for Controllers.cpp
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "Controllers.h"
#include "IptablesBaseTest.h"

namespace android {
namespace net {

class ControllersTest : public IptablesBaseTest {
  public:
    ControllersTest() {
        Controllers::execIptablesSilently = fakeExecIptables;
        Controllers::execIptablesRestore = fakeExecIptablesRestore;
    }

  protected:
    void initChildChains() { Controllers::initChildChains(); };
};

TEST_F(ControllersTest, TestInitIptablesRules) {
    ExpectedIptablesCommands expectedRestoreCommands = {
        { V4V6, "*filter\n"
                ":INPUT -\n"
                "-F INPUT\n"
                ":bw_INPUT -\n"
                "-A INPUT -j bw_INPUT\n"
                ":fw_INPUT -\n"
                "-A INPUT -j fw_INPUT\n"
                "COMMIT\n"
        },
        { V4V6, "*filter\n"
                ":FORWARD -\n"
                "-F FORWARD\n"
                ":oem_fwd -\n"
                "-A FORWARD -j oem_fwd\n"
                ":fw_FORWARD -\n"
                "-A FORWARD -j fw_FORWARD\n"
                ":bw_FORWARD -\n"
                "-A FORWARD -j bw_FORWARD\n"
                ":natctrl_FORWARD -\n"
                "-A FORWARD -j natctrl_FORWARD\n"
                "COMMIT\n"
        },
        { V4V6, "*raw\n"
                ":PREROUTING -\n"
                "-F PREROUTING\n"
                ":bw_raw_PREROUTING -\n"
                "-A PREROUTING -j bw_raw_PREROUTING\n"
                ":idletimer_raw_PREROUTING -\n"
                "-A PREROUTING -j idletimer_raw_PREROUTING\n"
                ":natctrl_raw_PREROUTING -\n"
                "-A PREROUTING -j natctrl_raw_PREROUTING\n"
                "COMMIT\n"
        },
        { V4V6, "*mangle\n"
                ":FORWARD -\n"
                "-F FORWARD\n"
                ":natctrl_mangle_FORWARD -\n"
                "-A FORWARD -j natctrl_mangle_FORWARD\n"
                "COMMIT\n"
        },
        { V4V6, "*mangle\n"
                ":INPUT -\n"
                "-F INPUT\n"
                ":wakeupctrl_mangle_INPUT -\n"
                "-A INPUT -j wakeupctrl_mangle_INPUT\n"
                ":routectrl_mangle_INPUT -\n"
                "-A INPUT -j routectrl_mangle_INPUT\n"
                "COMMIT\n"
        },
        { V4,   "*nat\n"
                ":PREROUTING -\n"
                "-F PREROUTING\n"
                ":oem_nat_pre -\n"
                "-A PREROUTING -j oem_nat_pre\n"
                "COMMIT\n"
        },
        { V4,   "*nat\n"
                ":POSTROUTING -\n"
                "-F POSTROUTING\n"
                ":natctrl_nat_POSTROUTING -\n"
                "-A POSTROUTING -j natctrl_nat_POSTROUTING\n"
                "COMMIT\n"
        },
        { V4V6, "*filter\n"
                ":oem_out -\n"
                "-A OUTPUT -j oem_out\n"
                ":fw_OUTPUT -\n"
                "-A OUTPUT -j fw_OUTPUT\n"
                ":st_OUTPUT -\n"
                "-A OUTPUT -j st_OUTPUT\n"
                ":bw_OUTPUT -\n"
                "-A OUTPUT -j bw_OUTPUT\n"
                "COMMIT\n"
        },
        { V4V6, "*mangle\n"
                ":oem_mangle_post -\n"
                "-A POSTROUTING -j oem_mangle_post\n"
                ":bw_mangle_POSTROUTING -\n"
                "-A POSTROUTING -j bw_mangle_POSTROUTING\n"
                ":idletimer_mangle_POSTROUTING -\n"
                "-A POSTROUTING -j idletimer_mangle_POSTROUTING\n"
                "COMMIT\n"
        },
    };
    initChildChains();
    expectIptablesRestoreCommands(expectedRestoreCommands);

    std::vector<std::string> expectedIptablesCommands = {
        "-t filter -D OUTPUT -j oem_out",
        "-t filter -D OUTPUT -j fw_OUTPUT",
        "-t filter -D OUTPUT -j st_OUTPUT",
        "-t filter -D OUTPUT -j bw_OUTPUT",
        "-t mangle -D POSTROUTING -j oem_mangle_post",
        "-t mangle -D POSTROUTING -j bw_mangle_POSTROUTING",
        "-t mangle -D POSTROUTING -j idletimer_mangle_POSTROUTING",
    };
    expectIptablesCommands(expectedIptablesCommands);

    // ... and nothing more.
    expectedRestoreCommands = {};
    expectIptablesRestoreCommands(expectedRestoreCommands);

    expectedIptablesCommands = {};
    expectIptablesCommands(expectedIptablesCommands);
}

}  // namespace net
}  // namespace android
