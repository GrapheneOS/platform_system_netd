/*
 * Copyright (C) 2016 The Android Open Source Project
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
 *
 */

#include <errno.h>
#include <sched.h>
#include <sys/capability.h>

#include <gtest/gtest.h>

TEST(NetUtilsWrapperTest, TestFileCapabilities) {
    errno = 0;
    ASSERT_EQ(NULL, cap_get_file("/system/bin/netutils-wrapper-1.0"));
    ASSERT_EQ(ENODATA, errno);
}

TEST(NetdSELinuxTest, CheckProperMTULabels) {
    // Since we expect the egrep regexp to filter everything out,
    // we thus expect no matches and thus a return code of 1
    // NOLINTNEXTLINE(cert-env33-c)
    ASSERT_EQ(W_EXITCODE(1, 0), system("ls -Z /sys/class/net/*/mtu | egrep -q -v "
                                       "'^u:object_r:sysfs_net:s0 /sys/class/net/'"));
}

// Trivial thread function that simply immediately terminates successfully.
static int thread(void*) {
    return 0;
}

typedef int (*thread_t)(void*);

static void nsTest(int flags, bool success, thread_t newThread) {
    // We need a minimal stack, but not clear if it will grow up or down,
    // So allocate 2 pages and give a pointer to the middle.
    static char stack[PAGE_SIZE * 2];
    errno = 0;
    // VFORK: if thread is successfully created, then kernel will wait for it
    // to terminate before we resume -> hence static stack is safe to reuse.
    int tid = clone(newThread, &stack[PAGE_SIZE], flags | CLONE_VFORK, NULL);
    if (success) {
        ASSERT_EQ(errno, 0);
        ASSERT_GE(tid, 0);
    } else {
        ASSERT_EQ(errno, EINVAL);
        ASSERT_EQ(tid, -1);
    }
}

// Test kernel configuration option CONFIG_NAMESPACES=y
TEST(NetdNamespaceTest, DISABLED_CheckMountNamespaceSupport) {
    nsTest(CLONE_NEWNS, true, thread);
}

// Test kernel configuration option CONFIG_UTS_NS=y
TEST(NetdNamespaceTest, DISABLED_CheckUTSNamespaceSupport) {
    nsTest(CLONE_NEWUTS, true, thread);
}

// Test kernel configuration option CONFIG_NET_NS=y
TEST(NetdNamespaceTest, DISABLED_CheckNetworkNamespaceSupport) {
    nsTest(CLONE_NEWNET, true, thread);
}

// Test kernel configuration option CONFIG_USER_NS=n
TEST(NetdNamespaceTest, DISABLED_CheckNoUserNamespaceSupport) {
    nsTest(CLONE_NEWUSER, false, thread);
}

// Test for all of the above
TEST(NetdNamespaceTest, DISABLED_CheckFullNamespaceSupport) {
    nsTest(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWNET, true, thread);
}
