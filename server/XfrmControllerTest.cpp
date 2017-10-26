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
 * xfrm_ctrl_test.cpp - unit tests for xfrm controllers.
 */

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <gmock/gmock.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>

#include "NetdConstants.h"
#include "NetlinkCommands.h"
#include "Stopwatch.h"
#include "XfrmController.h"
#include "android/net/INetd.h"
#include "android/net/UidRange.h"
#include "binder/IServiceManager.h"
#include "netdutils/MockSyscalls.h"
#include "netdutils/Netlink.h"
#include "tun_interface.h"

using android::base::unique_fd;
using android::netdutils::Fd;
using android::netdutils::MockSyscalls;
using android::netdutils::Slice;
using android::netdutils::Status;
using android::netdutils::StatusOr;
using android::netdutils::Syscalls;

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::Values;
using ::testing::WithArg;

/**
 * This gMock action works like SetArgPointee, but for netdutils::Slice.
 * It sets the memory which is pointed to by the N-th argument with the supplied value.
 */
ACTION_TEMPLATE(SetArgSlice, HAS_1_TEMPLATE_PARAMS(int, N), AND_1_VALUE_PARAMS(value)) {
    Slice orig = ::testing::get<N>(args);
    android::netdutils::copy(orig, value);
}

/**
 * This gMock action works like SaveArg, but is specialized for vector<iovec>.
 * It copies the memory pointed to by each of the iovecs into a single vector<uint8_t>.
 *
 * Flattening the iovec objects cannot be done later, since there is no guarantee that the memory
 * they point to will still be valid after the mock method returns.
 */
ACTION_TEMPLATE(SaveFlattenedIovecs, HAS_1_TEMPLATE_PARAMS(int, N), AND_1_VALUE_PARAMS(resVec)) {
    const std::vector<iovec>& iovs = ::testing::get<N>(args);

    for (const iovec& iov : iovs) {
        resVec->insert(resVec->end(), reinterpret_cast<uint8_t*>(iov.iov_base),
                       reinterpret_cast<uint8_t*>(iov.iov_base) + iov.iov_len);
    }
}

namespace android {
namespace net {

static constexpr int DROID_SPI = 0xD1201D;
static constexpr size_t KEY_LENGTH = 32;
static constexpr int NLMSG_DEFAULTSIZE = 8192;

static constexpr char LOCALHOST_V4[] = "127.0.0.1";
static constexpr char LOCALHOST_V6[] = "::1";
static constexpr char TEST_ADDR_V4[] = "8.8.8.8";
static constexpr char TEST_ADDR_V6[] = "2001:4860:4860::8888";

struct Policy {
    xfrm_userpolicy_info info;
    xfrm_user_tmpl tmpl;
};

struct NetlinkResponse {
    nlmsghdr hdr;
    char buf[NLMSG_DEFAULTSIZE];
};

void expectAddressEquals(int family, const std::string& expected, const xfrm_address_t& actual) {
    char actualStr[INET6_ADDRSTRLEN];
    const char* ret =
        inet_ntop(family, reinterpret_cast<const void*>(&actual), actualStr, INET6_ADDRSTRLEN);
    EXPECT_NE(nullptr, ret) << "Unable to convert xfrm_address_t to string";
    EXPECT_EQ(expected, actualStr);
}

class XfrmControllerTest : public ::testing::Test {
public:
    MockSyscalls mockSyscalls;

    void SetUp() override { netdutils::sSyscalls.swap(mockSyscalls); }
};

// Test class allowing IPv4/IPv6 parameterized tests.
class XfrmControllerParameterizedTest : public XfrmControllerTest,
                                        public ::testing::WithParamInterface<int> {};

// Helper to make generated test names readable.
std::string FamilyName(::testing::TestParamInfo<int> info) {
    return (info.param == AF_INET) ? "AF_INET" : "AF_INET6";
}

// The TEST_P cases below will run with each of the following value parameters.
INSTANTIATE_TEST_CASE_P(ByFamily, XfrmControllerParameterizedTest, Values(AF_INET, AF_INET6),
                        FamilyName);

TEST_P(XfrmControllerParameterizedTest, TestIpSecAllocateSpi) {
    const int family = GetParam();
    const std::string localAddr = (family == AF_INET6) ? LOCALHOST_V6 : LOCALHOST_V4;
    const std::string remoteAddr = (family == AF_INET6) ? TEST_ADDR_V6 : TEST_ADDR_V4;

    NetlinkResponse response{};
    response.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;
    Slice responseSlice = netdutils::makeSlice(response);

    size_t expectedMsgLength = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(xfrm_userspi_info));

    // A vector to hold the flattened netlink message for nlMsgSlice
    std::vector<uint8_t> nlMsgBuf;
    EXPECT_CALL(mockSyscalls, writev(_, _))
        .WillOnce(DoAll(SaveFlattenedIovecs<1>(&nlMsgBuf), Return(expectedMsgLength)));
    EXPECT_CALL(mockSyscalls, read(_, _))
        .WillOnce(DoAll(SetArgSlice<1>(responseSlice), Return(responseSlice)));

    XfrmController ctrl;
    int outSpi = 0;
    Status res = ctrl.ipSecAllocateSpi(1 /* resourceId */, static_cast<int>(XfrmDirection::OUT),
                                       localAddr, remoteAddr, DROID_SPI, &outSpi);

    EXPECT_TRUE(isOk(res)) << res;
    EXPECT_EQ(DROID_SPI, outSpi);
    EXPECT_EQ(expectedMsgLength, nlMsgBuf.size());

    Slice nlMsgSlice = netdutils::makeSlice(nlMsgBuf);
    nlMsgSlice = drop(nlMsgSlice, NLMSG_HDRLEN);

    xfrm_userspi_info userspi{};
    netdutils::extract(nlMsgSlice, userspi);

    EXPECT_EQ(family, userspi.info.sel.family);
    expectAddressEquals(family, localAddr, userspi.info.saddr);
    expectAddressEquals(family, remoteAddr, userspi.info.id.daddr);

    EXPECT_EQ(DROID_SPI, static_cast<int>(userspi.min));
    EXPECT_EQ(DROID_SPI, static_cast<int>(userspi.max));
}

TEST_P(XfrmControllerParameterizedTest, TestIpSecAddSecurityAssociation) {
    const int family = GetParam();
    const std::string localAddr = (family == AF_INET6) ? LOCALHOST_V6 : LOCALHOST_V4;
    const std::string remoteAddr = (family == AF_INET6) ? TEST_ADDR_V6 : TEST_ADDR_V4;

    NetlinkResponse response{};
    response.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;
    Slice responseSlice = netdutils::makeSlice(response);

    std::vector<uint8_t> authKey(KEY_LENGTH, 0);
    std::vector<uint8_t> cryptKey(KEY_LENGTH, 1);

    // Calculate the length of the expected netlink message.
    size_t expectedMsgLength =
        NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(xfrm_usersa_info)) +
        NLA_ALIGN(offsetof(XfrmController::nlattr_algo_crypt, key) + KEY_LENGTH) +
        NLA_ALIGN(offsetof(XfrmController::nlattr_algo_auth, key) + KEY_LENGTH);

    std::vector<uint8_t> nlMsgBuf;
    EXPECT_CALL(mockSyscalls, writev(_, _))
        .WillOnce(DoAll(SaveFlattenedIovecs<1>(&nlMsgBuf), Return(expectedMsgLength)));
    EXPECT_CALL(mockSyscalls, read(_, _))
        .WillOnce(DoAll(SetArgSlice<1>(responseSlice), Return(responseSlice)));

    XfrmController ctrl;
    Status res = ctrl.ipSecAddSecurityAssociation(
        1 /* resourceId */, static_cast<int>(XfrmMode::TUNNEL),
        static_cast<int>(XfrmDirection::OUT), localAddr, remoteAddr, 0 /* underlying network */,
        DROID_SPI, "hmac(sha256)" /* auth algo */, authKey, 128 /* auth trunc length */,
        "cbc(aes)" /* encryption algo */, cryptKey, 0 /* crypt trunc length? */, "" /* AEAD algo */,
        {}, 0, static_cast<int>(XfrmEncapType::NONE), 0 /* local port */, 0 /* remote port */);

    EXPECT_TRUE(isOk(res)) << res;
    EXPECT_EQ(expectedMsgLength, nlMsgBuf.size());

    Slice nlMsgSlice = netdutils::makeSlice(nlMsgBuf);
    nlMsgSlice = drop(nlMsgSlice, NLMSG_HDRLEN);

    xfrm_usersa_info usersa{};
    netdutils::extract(nlMsgSlice, usersa);

    EXPECT_EQ(family, usersa.family);
    EXPECT_EQ(1 /* Transform Id*/, static_cast<int>(usersa.reqid));
    EXPECT_EQ(XFRM_MODE_TUNNEL, usersa.mode);
    EXPECT_EQ(htonl(DROID_SPI), usersa.id.spi);
    EXPECT_EQ(IPPROTO_ESP, usersa.id.proto);

    expectAddressEquals(family, localAddr, usersa.saddr);
    expectAddressEquals(family, remoteAddr, usersa.id.daddr);

    // Extract and check the encryption/authentication algorithms.
    Slice attr_buf = drop(nlMsgSlice, NLA_ALIGN(sizeof(xfrm_usersa_info)));

    // Extract and check the encryption/authentication algorithm
    XfrmController::nlattr_algo_crypt encryptAlgo{};
    XfrmController::nlattr_algo_auth authAlgo{};
    auto attrHandler = [&encryptAlgo, &authAlgo](const nlattr& attr, const Slice& attr_payload) {
        Slice buf = attr_payload;
        if (attr.nla_type == XFRMA_ALG_CRYPT) {
            encryptAlgo.hdr = attr;
            netdutils::extract(buf, encryptAlgo.crypt);
            buf = drop(buf, sizeof(xfrm_algo));
            netdutils::extract(buf, encryptAlgo.key);
        } else if (attr.nla_type == XFRMA_ALG_AUTH_TRUNC) {
            authAlgo.hdr = attr;
            netdutils::extract(buf, authAlgo.auth);
            buf = drop(buf, sizeof(xfrm_algo_auth));
            netdutils::extract(buf, authAlgo.key);
        } else {
            FAIL() << "Unexpected nlattr type: " << attr.nla_type;
        }
    };
    forEachNetlinkAttribute(attr_buf, attrHandler);

    // TODO: Use ContainerEq or ElementsAreArray to get better test failure messages.
    EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(cryptKey.data()),
                        reinterpret_cast<void*>(&encryptAlgo.key), KEY_LENGTH));
    EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(authKey.data()),
                        reinterpret_cast<void*>(&authAlgo.key), KEY_LENGTH));
}

TEST_F(XfrmControllerTest, TestIpSecAddSecurityAssociationIPv4Encap) {
    // TODO: Implement this test, which is nearly identical to
    // TestIpSecAddSecurityAssociation.
}

// Test that input validation rejects IPv6 UDP encap.
TEST_F(XfrmControllerTest, TestIpSecAddSecurityAssociationIPv6Encap) {
    EXPECT_CALL(mockSyscalls, writev(_, _)).Times(0);

    XfrmController ctrl;
    Status res = ctrl.ipSecAddSecurityAssociation(
        1, static_cast<int>(XfrmMode::TUNNEL), static_cast<int>(XfrmDirection::OUT), LOCALHOST_V6,
        TEST_ADDR_V6, 0, DROID_SPI, "hmac(sha256)", {}, 128, "cbc(aes)", {}, 0, "", {}, 0,
        static_cast<int>(XfrmEncapType::ESPINUDP_NON_IKE), 0, 0);

    EXPECT_FALSE(isOk(res)) << "IPv6 UDP encap not rejected";
}

TEST_P(XfrmControllerParameterizedTest, TestIpSecApplyTransportModeTransform) {
    const int family = GetParam();
    const std::string localAddr = (family == AF_INET6) ? LOCALHOST_V6 : LOCALHOST_V4;
    const std::string remoteAddr = (family == AF_INET6) ? TEST_ADDR_V6 : TEST_ADDR_V4;

    size_t optlen = 0;
    Policy policy{};
    // Need to cast from void* in order to "SaveArg" policy. Easier to invoke a
    // lambda than to write a gMock action.
    auto SavePolicy = [&policy](const void* value) {
        policy = *reinterpret_cast<const Policy*>(value);
    };

    struct sockaddr socketaddr;
    socketaddr.sa_family = family;

    unique_fd sock(socket(family, SOCK_STREAM, 0));

    EXPECT_CALL(mockSyscalls, getsockname(_, _, _))
        .WillOnce(DoAll(SetArgPointee<1>(socketaddr), Return(netdutils::status::ok)));

    EXPECT_CALL(mockSyscalls, setsockopt(_, _, _, _, _))
        .WillOnce(DoAll(WithArg<3>(Invoke(SavePolicy)), SaveArg<4>(&optlen),
                        Return(netdutils::status::ok)));

    XfrmController ctrl;
    Status res = ctrl.ipSecApplyTransportModeTransform(sock, 1 /* resourceId */,
                                                       static_cast<int>(XfrmDirection::OUT),
                                                       localAddr, remoteAddr, DROID_SPI);

    EXPECT_TRUE(isOk(res)) << res;
    EXPECT_EQ(sizeof(Policy), optlen);

    EXPECT_EQ(1 /* resourceId */, static_cast<int>(policy.tmpl.reqid));
    EXPECT_EQ(htonl(DROID_SPI), policy.tmpl.id.spi);

    expectAddressEquals(family, localAddr, policy.tmpl.saddr);
    expectAddressEquals(family, remoteAddr, policy.tmpl.id.daddr);
}

TEST_P(XfrmControllerParameterizedTest, TestIpSecDeleteSecurityAssociation) {
    const int family = GetParam();
    const std::string localAddr = (family == AF_INET6) ? LOCALHOST_V6 : LOCALHOST_V4;
    const std::string remoteAddr = (family == AF_INET6) ? TEST_ADDR_V6 : TEST_ADDR_V4;

    NetlinkResponse response{};
    response.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;
    Slice responseSlice = netdutils::makeSlice(response);

    size_t expectedMsgLength = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(xfrm_usersa_id));

    std::vector<uint8_t> nlMsgBuf;
    EXPECT_CALL(mockSyscalls, writev(_, _))
        .WillOnce(DoAll(SaveFlattenedIovecs<1>(&nlMsgBuf), Return(expectedMsgLength)));
    EXPECT_CALL(mockSyscalls, read(_, _))
        .WillOnce(DoAll(SetArgSlice<1>(responseSlice), Return(responseSlice)));

    XfrmController ctrl;
    Status res = ctrl.ipSecDeleteSecurityAssociation(
        1 /* resourceId */, static_cast<int>(XfrmDirection::OUT), localAddr, remoteAddr, DROID_SPI);

    EXPECT_TRUE(isOk(res)) << res;
    EXPECT_EQ(expectedMsgLength, nlMsgBuf.size());

    Slice nlMsgSlice = netdutils::makeSlice(nlMsgBuf);
    nlMsgSlice = netdutils::drop(nlMsgSlice, NLMSG_HDRLEN);

    xfrm_usersa_id said{};
    netdutils::extract(nlMsgSlice, said);

    EXPECT_EQ(htonl(DROID_SPI), said.spi);
    expectAddressEquals(family, remoteAddr, said.daddr);
}

} // namespace net
} // namespace android
