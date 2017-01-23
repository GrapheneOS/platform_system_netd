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
 */

#include <string>

#include <gtest/gtest.h>

#include "IptablesRestoreController.h"
#include "NetdConstants.h"

class IptablesRestoreControllerHolder {
public:
  IptablesRestoreControllerHolder() {
      IptablesRestoreController::installSignalHandler(&ctrl);
  }

  IptablesRestoreController ctrl;
};

IptablesRestoreControllerHolder holder;

TEST(IptablesRestoreControllerTest, TestBasicCommand) {
  IptablesRestoreController& con = holder.ctrl;
  EXPECT_EQ(0, con.execute(IptablesTarget::V4, "#Test\n"));
  EXPECT_EQ(0, con.execute(IptablesTarget::V4V6, "#Test\n"));
  EXPECT_EQ(0, con.execute(IptablesTarget::V6, "#Test\n"));
}

TEST(IptablesRestoreControllerTest, TestRestartOnMalformedCommand) {
  IptablesRestoreController& con = holder.ctrl;
  EXPECT_EQ(-1, con.execute(IptablesTarget::V4V6, "malformed command\n"));
  EXPECT_EQ(0, con.execute(IptablesTarget::V4V6, "#Test\n"));
}
