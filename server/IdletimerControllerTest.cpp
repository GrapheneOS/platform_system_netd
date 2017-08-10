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
 * IdletimerControllerTest.cpp - unit tests for IdletimerController.cpp
 */

#include <gtest/gtest.h>

#include <android-base/strings.h>
#include <android-base/stringprintf.h>

#include "IdletimerController.h"
#include "IptablesBaseTest.h"

using android::base::StringPrintf;

class IdletimerControllerTest : public IptablesBaseTest {
protected:
    IdletimerControllerTest() {
        IdletimerController::execFunction = fake_android_fork_exec;
    }
    IdletimerController mIt;
};

TEST_F(IdletimerControllerTest, TestSetupIptablesHooks) {
    mIt.setupIptablesHooks();
    expectIptablesCommands(ExpectedIptablesCommands{});
    expectIptablesRestoreCommands(ExpectedIptablesCommands{});
}

TEST_F(IdletimerControllerTest, TestEnableDisable) {
    std::vector<std::string> expected = {
        "-t raw -F idletimer_raw_PREROUTING",
        "-t mangle -F idletimer_mangle_POSTROUTING",
    };

    mIt.enableIdletimerControl();
    expectIptablesCommands(expected);

    mIt.enableIdletimerControl();
    expectIptablesCommands(expected);

    mIt.disableIdletimerControl();
    expectIptablesCommands(expected);

    mIt.disableIdletimerControl();
    expectIptablesCommands(expected);
}

const std::vector<std::string> makeAddRemoveCommands(bool add) {
    const char *op = add ? "-A" : "-D";
    return {
        StringPrintf("-t raw %s idletimer_raw_PREROUTING -i wlan0 -j IDLETIMER"
                     " --timeout 12345 --label hello --send_nl_msg 1", op),
        StringPrintf("-t mangle %s idletimer_mangle_POSTROUTING -o wlan0 -j IDLETIMER"
                     " --timeout 12345 --label hello --send_nl_msg 1", op),
    };
}

TEST_F(IdletimerControllerTest, TestAddRemove) {
    auto expected = makeAddRemoveCommands(true);
    mIt.addInterfaceIdletimer("wlan0", 12345, "hello");
    expectIptablesCommands(expected);

    mIt.addInterfaceIdletimer("wlan0", 12345, "hello");
    expectIptablesCommands(expected);

    expected = makeAddRemoveCommands(false);
    mIt.removeInterfaceIdletimer("wlan0", 12345, "hello");
    expectIptablesCommands(expected);

    mIt.removeInterfaceIdletimer("wlan0", 12345, "hello");
    expectIptablesCommands(expected);
}
