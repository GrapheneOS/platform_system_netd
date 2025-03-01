/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <unistd.h>

#include <android-base/properties.h>
#include <gtest/gtest.h>
#include <vintf/VintfObject.h>

#include <fstream>
#include <string>
#include <unordered_set>

#include "bpf/KernelUtils.h"

namespace android {
namespace net {

namespace {

using ::android::base::GetProperty;
using ::android::vintf::RuntimeInfo;
using ::android::vintf::VintfObject;

class KernelConfigVerifier final {
  public:
    KernelConfigVerifier() : mRuntimeInfo(VintfObject::GetRuntimeInfo()) {
        std::ifstream procModules("/proc/modules", std::ios::in);
        if (!procModules) {
            // Return early, this will likely cause the test to fail. However, gtest FAIL() cannot
            // be used outside of an actual test method.
            return;
        }
        std::string modline;
        while (std::getline(procModules, modline)) {
            // modline contains a single line read from /proc/modules. For example:
            // virtio_snd 45056 0 - Live 0x0000000000000000 (E)
            mLoadedModules.emplace(modline.substr(0, modline.find(' ')));
        }
    }

    bool hasOption(const std::string& option) const {
        const auto& configMap = mRuntimeInfo->kernelConfigs();
        auto it = configMap.find(option);
        if (it != configMap.cend()) {
            return it->second == "y";
        }
        return false;
    }

    bool hasModule(const std::string& option) const {
        const auto& configMap = mRuntimeInfo->kernelConfigs();
        auto it = configMap.find(option);
        if (it != configMap.cend()) {
            return (it->second == "y") || (it->second == "m");
        }
        return false;
    }

    bool isAvailable(const std::string& option, const std::string& koName) const {
        return hasOption(option) || mLoadedModules.contains(koName);
    }

  private:
    std::shared_ptr<const RuntimeInfo> mRuntimeInfo;
    std::unordered_set<std::string> mLoadedModules;
};

bool isCuttlefish() {
    return GetProperty("ro.product.board", "") == "cutf";
}

}  // namespace

/**
 * If this test fails, enable the following kernel modules in your kernel config:
 * CONFIG_NET_CLS_MATCHALL=y
 * CONFIG_NET_ACT_POLICE=y
 * CONFIG_NET_ACT_BPF=y
 * CONFIG_BPF_JIT=y
 */
TEST(KernelTest, TestRateLimitingSupport) {
    KernelConfigVerifier configVerifier;
    EXPECT_TRUE(configVerifier.hasOption("CONFIG_NET_CLS_MATCHALL"));
    EXPECT_TRUE(configVerifier.hasOption("CONFIG_NET_ACT_POLICE"));
    EXPECT_TRUE(configVerifier.hasOption("CONFIG_NET_ACT_BPF"));
    EXPECT_TRUE(configVerifier.hasOption("CONFIG_BPF_JIT"));
}

TEST(KernelTest, TestRequireBpfUnprivDefaultOn) {
    KernelConfigVerifier configVerifier;
    EXPECT_FALSE(configVerifier.hasOption("CONFIG_BPF_UNPRIV_DEFAULT_OFF"));
}

TEST(KernelTest, TestBpfJitAlwaysOn) {
    KernelConfigVerifier configVerifier;
    ASSERT_TRUE(configVerifier.hasOption("CONFIG_BPF_JIT_ALWAYS_ON"));
}

TEST(KernelTest, TestHaveEfficientUnalignedAccess) {
    // Turns out the bpf verifier is stricter if you don't have this option.
    // At least *some* of our bpf code fails to verify without it.
    KernelConfigVerifier configVerifier;
    ASSERT_TRUE(configVerifier.hasOption("CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS"));
}

/* Android 14/U should only launch on 64-bit kernels
 *   T launches on 5.10/5.15
 *   U launches on 5.15/6.1
 * So >=5.16 implies isKernel64Bit()
 */
TEST(KernelTest, TestKernel64Bit) {
    if (!bpf::isAtLeastKernelVersion(5, 16, 0)) GTEST_SKIP() << "Exempt on < 5.16 kernel.";
    ASSERT_TRUE(bpf::isKernel64Bit());
}

// Android V requires x86 kernels to be 64-bit, as among other things
// 32-bit x86 kernels have subtly different structure layouts for XFRM
TEST(KernelTest, TestX86Kernel64Bit) {
    if (!bpf::isX86()) GTEST_SKIP() << "Exempt on non-x86 architecture.";
    ASSERT_TRUE(bpf::isKernel64Bit());
}

// Android 25Q2 requires 64-bit userspace on new 6.7+ kernels.
TEST(KernelTest, DISABLED_TestUser64Bit) {
    if (!bpf::isAtLeastKernelVersion(6, 7, 0)) GTEST_SKIP() << "Exempt on < 6.7 kernel.";
    ASSERT_TRUE(bpf::isUserspace64bit());
}

// Android 25Q2 requires 5.4+
TEST(KernelTest, TestKernel54) {
    ASSERT_TRUE(bpf::isAtLeastKernelVersion(5, 4, 0));
}

// RiscV is not yet supported: make it fail VTS.
TEST(KernelTest, TestNotRiscV) {
    ASSERT_TRUE(!bpf::isRiscV());
}

TEST(KernelTest, TestIsLTS) {
    ASSERT_TRUE(bpf::isLtsKernel());
}

static bool exists(const char* filename) {
    return !access(filename, F_OK);
}

static bool isGSI() {
    // From //system/gsid/libgsi.cpp IsGsiRunning()
    return exists("/metadata/gsi/dsu/booted");
}

#define ifIsKernelThenMinLTS(major, minor, sub) do { \
    if (isGSI()) GTEST_SKIP() << "Test is meaningless on GSI."; \
    if (!bpf::isKernelVersion((major), (minor))) GTEST_SKIP() << "Not for this LTS ver."; \
    ASSERT_TRUE(bpf::isAtLeastKernelVersion((major), (minor), (sub))); \
} while (0)

TEST(KernelTest, TestMinRequiredLTS_5_4)  { ifIsKernelThenMinLTS(5, 4, 277); }
TEST(KernelTest, TestMinRequiredLTS_5_10) { ifIsKernelThenMinLTS(5, 10, 210); }
TEST(KernelTest, TestMinRequiredLTS_5_15) { ifIsKernelThenMinLTS(5, 15, 149); }
TEST(KernelTest, TestMinRequiredLTS_6_1)  { ifIsKernelThenMinLTS(6, 1, 78); }
TEST(KernelTest, TestMinRequiredLTS_6_6)  { ifIsKernelThenMinLTS(6, 6, 30); }
TEST(KernelTest, TestMinRequiredLTS_6_12) { ifIsKernelThenMinLTS(6, 12, 13); }

TEST(KernelTest, TestSupportsAcceptRaMinLft) {
    if (isGSI()) GTEST_SKIP() << "Meaningless on GSI due to ancient kernels.";
    if (!bpf::isAtLeastKernelVersion(5, 10, 0)) GTEST_SKIP() << "Too old base kernel.";
    ASSERT_TRUE(exists("/proc/sys/net/ipv6/conf/default/accept_ra_min_lft"));
}

TEST(KernelTest, TestSupportsCommonUsbEthernetDongles) {
    KernelConfigVerifier configVerifier;
    if (!configVerifier.hasModule("CONFIG_USB")) GTEST_SKIP() << "Exempt without USB support.";
    EXPECT_TRUE(configVerifier.hasModule("CONFIG_USB_NET_AX8817X"));
    EXPECT_TRUE(configVerifier.hasModule("CONFIG_USB_NET_AX88179_178A"));
    EXPECT_TRUE(configVerifier.hasModule("CONFIG_USB_NET_CDCETHER"));
    EXPECT_TRUE(configVerifier.hasModule("CONFIG_USB_NET_CDC_EEM"));
    EXPECT_TRUE(configVerifier.hasModule("CONFIG_USB_NET_CDC_NCM"));
    if (bpf::isAtLeastKernelVersion(5, 4, 0))
        EXPECT_TRUE(configVerifier.hasModule("CONFIG_USB_NET_AQC111"));

    EXPECT_TRUE(configVerifier.hasModule("CONFIG_USB_RTL8152"));
    EXPECT_TRUE(configVerifier.hasModule("CONFIG_USB_RTL8150"));
    if (bpf::isAtLeastKernelVersion(5, 15, 0)) {
        EXPECT_TRUE(configVerifier.hasModule("CONFIG_USB_RTL8153_ECM"));
        EXPECT_TRUE(configVerifier.hasModule("CONFIG_AX88796B_PHY"));
    }
}

/**
 * In addition to TestSupportsCommonUsbEthernetDongles, ensure that USB CDC host drivers are either
 * builtin or loaded on physical devices.
 */
// TODO: check for hasSystemFeature(FEATURE_USB_HOST)
TEST(KernelTest, TestSupportsUsbCdcHost) {
    KernelConfigVerifier configVerifier;
    // TODO: Load these modules on cuttlefish.
    if (isCuttlefish()) GTEST_SKIP() << "Exempt on cuttlefish";

    EXPECT_TRUE(configVerifier.isAvailable("CONFIG_USB_NET_CDC_NCM", "cdc_ncm"));
    EXPECT_TRUE(configVerifier.isAvailable("CONFIG_USB_NET_CDC_EEM", "cdc_eem"));
    EXPECT_TRUE(configVerifier.isAvailable("CONFIG_USB_NET_CDCETHER", "cdc_ether"));
}

// TODO: check for hasSystemFeature(FEATURE_USB_ACCESSORY)
TEST(KernelTest, TestSupportsUsbNcmGadget) {
    KernelConfigVerifier configVerifier;
    EXPECT_TRUE(configVerifier.isAvailable("CONFIG_USB_F_NCM", "usb_f_ncm"));
    EXPECT_TRUE(configVerifier.hasOption("CONFIG_USB_CONFIGFS_NCM"));
}

}  // namespace net
}  // namespace android
