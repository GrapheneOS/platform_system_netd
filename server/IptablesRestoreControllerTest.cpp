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
#include <fcntl.h>
#include <signal.h>

#include <gtest/gtest.h>

#define LOG_TAG "IptablesRestoreControllerTest"
#include <cutils/log.h>
#include <android-base/stringprintf.h>

#include "IptablesRestoreController.h"
#include "NetdConstants.h"

using android::base::StringPrintf;

class IptablesRestoreControllerTest : public ::testing::Test {
public:
  IptablesRestoreController con;

  pid_t getIpRestorePid(const IptablesRestoreController::IptablesProcessType type) {
      return con.getIpRestorePid(type);
  };

  void expectNoIptablesRestoreProcess(pid_t pid) {
    // We can't readlink /proc/PID/exe, because zombie processes don't have it.
    // Parse /proc/PID/stat instead.
    std::string statPath = StringPrintf("/proc/%d/stat", pid);
    int fd = open(statPath.c_str(), O_RDONLY);
    if (fd == -1) {
      // ENOENT means the process is gone (expected).
      ASSERT_EQ(errno, ENOENT)
        << "Unexpected error opening " << statPath << ": " << strerror(errno);
      return;
    }

    // If the PID exists, it's possible (though very unlikely) that the PID was reused. Check the
    // binary name as well, to ensure the test isn't flaky.
    char statBuf[1024];
    ASSERT_NE(-1, read(fd, statBuf, sizeof(statBuf)))
        << "Could not read from " << statPath << ": " << strerror(errno);
    close(fd);

    std::string statString(statBuf);
    EXPECT_FALSE(statString.find("iptables-restor") || statString.find("ip6tables-resto"))
      << "Previous iptables-restore pid " << pid << " still alive: " << statString;
  }
};

TEST_F(IptablesRestoreControllerTest, TestBasicCommand) {
  EXPECT_EQ(0, con.execute(IptablesTarget::V4V6, "#Test\n"));

  pid_t pid4 = getIpRestorePid(IptablesRestoreController::IPTABLES_PROCESS);
  pid_t pid6 = getIpRestorePid(IptablesRestoreController::IP6TABLES_PROCESS);

  EXPECT_EQ(0, con.execute(IptablesTarget::V6, "#Test\n"));
  EXPECT_EQ(0, con.execute(IptablesTarget::V4, "#Test\n"));

  // Check the PIDs are the same as they were before. If they're not, the child processes were
  // restarted, which causes a 30-60ms delay.
  EXPECT_EQ(pid4, getIpRestorePid(IptablesRestoreController::IPTABLES_PROCESS));
  EXPECT_EQ(pid6, getIpRestorePid(IptablesRestoreController::IP6TABLES_PROCESS));
}

TEST_F(IptablesRestoreControllerTest, TestRestartOnMalformedCommand) {
  for (int i = 0; i < 50; i++) {
      IptablesTarget target = (IptablesTarget) (i % 3);
      ASSERT_EQ(-1, con.execute(target, "malformed command\n")) <<
          "Malformed command did not fail at iteration " << i;
      ASSERT_EQ(0, con.execute(target, "#Test\n")) <<
          "No-op command did not succeed at iteration " << i;
  }
}

TEST_F(IptablesRestoreControllerTest, TestRestartOnProcessDeath) {
  // Run a command to ensure that the processes are running.
  EXPECT_EQ(0, con.execute(IptablesTarget::V4V6, "#Test\n"));

  pid_t pid4 = getIpRestorePid(IptablesRestoreController::IPTABLES_PROCESS);
  pid_t pid6 = getIpRestorePid(IptablesRestoreController::IP6TABLES_PROCESS);

  ASSERT_EQ(0, kill(pid4, 0)) << "iptables-restore pid " << pid4 << " does not exist";
  ASSERT_EQ(0, kill(pid6, 0)) << "ip6tables-restore pid " << pid6 << " does not exist";
  ASSERT_EQ(0, kill(pid4, SIGTERM)) << "Failed to send SIGTERM to iptables-restore pid " << pid4;
  ASSERT_EQ(0, kill(pid6, SIGTERM)) << "Failed to send SIGTERM to ip6tables-restore pid " << pid6;

  // Wait 100ms for processes to terminate.
  TEMP_FAILURE_RETRY(usleep(100 * 1000));

  // Ensure that running a new command properly restarts the processes.
  EXPECT_EQ(0, con.execute(IptablesTarget::V4V6, "#Test\n"));
  EXPECT_NE(pid4, getIpRestorePid(IptablesRestoreController::IPTABLES_PROCESS));
  EXPECT_NE(pid6, getIpRestorePid(IptablesRestoreController::IP6TABLES_PROCESS));

  // Check there are no zombies.
  expectNoIptablesRestoreProcess(pid4);
  expectNoIptablesRestoreProcess(pid6);
}
