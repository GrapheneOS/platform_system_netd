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

using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::WithArg;
using ::testing::_;

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

TEST_F(XfrmControllerTest, TestIpSecAllocateSpi) {
    int outSpi = 0;
    XfrmController ctrl;

    NetlinkResponse response = {};
    response.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;

    /** It's an injected return result for the sendMessage function to go through */
    StatusOr<Slice> readStatus(netdutils::makeSlice(response));

    size_t expectMsgLength = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(xfrm_userspi_info));

    // Set the return to allow the program go through
    StatusOr<size_t> expectRet(expectMsgLength);

    // A vector to hold the flattened netlink message for nlMsgSlice
    std::vector<uint8_t> nlMsgBuf;
    EXPECT_CALL(mockSyscalls, writev(_, _))
        .WillOnce(DoAll(SaveFlattenedIovecs<1>(&nlMsgBuf), Return(expectRet)));
    EXPECT_CALL(mockSyscalls, read(_, _))
        .WillOnce(DoAll(SetArgSlice<1>(netdutils::makeSlice(response)), Return(readStatus)));

    Status res = ctrl.ipSecAllocateSpi(
        1 /* resourceId */, static_cast<int>(XfrmDirection::OUT), "127.0.0.1" /* local address */,
        "8.8.8.8" /* remote address */, DROID_SPI /* request spi */, &outSpi);

    EXPECT_TRUE(isOk(res)) << res;
    EXPECT_EQ(DROID_SPI, outSpi);
    EXPECT_EQ(expectMsgLength, nlMsgBuf.size());

    Slice nlMsgSlice = netdutils::makeSlice(nlMsgBuf);
    nlMsgSlice = drop(nlMsgSlice, NLMSG_HDRLEN);

    xfrm_userspi_info userspi{};
    netdutils::extract(nlMsgSlice, userspi);

    EXPECT_EQ(AF_INET, userspi.info.sel.family);

    expectAddressEquals(AF_INET, "127.0.0.1", userspi.info.saddr);
    expectAddressEquals(AF_INET, "8.8.8.8", userspi.info.id.daddr);

    EXPECT_EQ(DROID_SPI, static_cast<int>(userspi.min));
    EXPECT_EQ(DROID_SPI, static_cast<int>(userspi.max));
}

TEST_F(XfrmControllerTest, TestIpSecAllocateSpiIpv6) {
    int outSpi = 0;
    XfrmController ctrl;

    NetlinkResponse response = {};
    response.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;

    /** It's an injected return result for the sendMessage function to go through */
    StatusOr<Slice> readStatus(netdutils::makeSlice(response));

    size_t expectMsgLength = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(xfrm_userspi_info));
    // Set the return to allow the program go through
    StatusOr<size_t> expectRet(expectMsgLength);

    // A vector to hold the flattened netlink message for nlMsgSlice
    std::vector<uint8_t> nlMsgBuf;
    EXPECT_CALL(mockSyscalls, writev(_, _))
        .WillOnce(DoAll(SaveFlattenedIovecs<1>(&nlMsgBuf), Return(expectRet)));
    EXPECT_CALL(mockSyscalls, read(_, _))
        .WillOnce(DoAll(SetArgSlice<1>(netdutils::makeSlice(response)), Return(readStatus)));

    Status res = ctrl.ipSecAllocateSpi(
        1 /* resourceId */, static_cast<int>(XfrmDirection::OUT), "::1" /* local address */,
        "2001:4860:4860::8888" /* remote address */, DROID_SPI /* request spi */, &outSpi);

    EXPECT_TRUE(isOk(res)) << res;
    EXPECT_EQ(DROID_SPI, outSpi);
    EXPECT_EQ(expectMsgLength, nlMsgBuf.size());

    Slice nlMsgSlice = netdutils::makeSlice(nlMsgBuf);
    nlMsgSlice = drop(nlMsgSlice, NLMSG_HDRLEN);

    xfrm_userspi_info userspi{};
    netdutils::extract(nlMsgSlice, userspi);

    EXPECT_EQ(AF_INET6, userspi.info.sel.family);

    expectAddressEquals(AF_INET6, "::1", userspi.info.saddr);
    expectAddressEquals(AF_INET6, "2001:4860:4860::8888", userspi.info.id.daddr);

    EXPECT_EQ(DROID_SPI, static_cast<int>(userspi.min));
    EXPECT_EQ(DROID_SPI, static_cast<int>(userspi.max));
}

TEST_F(XfrmControllerTest, TestIpSecAddSecurityAssociation) {

    int reqSpi = DROID_SPI;
    XfrmController ctrl;

    NetlinkResponse response = {};
    response.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;

    /** It's an injected return result for the sendMessage function to go through */
    StatusOr<Slice> readStatus(netdutils::makeSlice(response));

    std::vector<uint8_t> authKey(KEY_LENGTH, 0);
    std::vector<uint8_t> cryptKey(KEY_LENGTH, 1);

    // Calculate the length of the expected netlink message.
    size_t expectMsgLength =
        NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(xfrm_usersa_info)) +
        NLA_ALIGN(offsetof(XfrmController::nlattr_algo_crypt, key) + KEY_LENGTH) +
        NLA_ALIGN(offsetof(XfrmController::nlattr_algo_auth, key) + KEY_LENGTH) +
        NLA_ALIGN(sizeof(XfrmController::nlattr_encap_tmpl));
    StatusOr<size_t> expectRet(expectMsgLength);

    std::vector<uint8_t> nlMsgBuf;
    EXPECT_CALL(mockSyscalls, writev(_, _))
        .WillOnce(DoAll(SaveFlattenedIovecs<1>(&nlMsgBuf), Return(expectRet)));
    EXPECT_CALL(mockSyscalls, read(_, _))
        .WillOnce(DoAll(SetArgSlice<1>(netdutils::makeSlice(response)), Return(readStatus)));

    Status res = ctrl.ipSecAddSecurityAssociation(
        1 /* resourceId */, static_cast<int>(XfrmMode::TUNNEL),
        static_cast<int>(XfrmDirection::OUT), "127.0.0.1" /* local address */,
        "8.8.8.8" /* remote address */, 0 /* network handle */, reqSpi,
        "hmac(sha256)" /* auth algo */, authKey, 0, "cbc(aes)" /* encryption algo */, cryptKey, 0,
        "" /* AEAD algo */, {}, 0, UDP_ENCAP_ESPINUDP_NON_IKE /* encapType */,
        34567 /* local port */, 34567 /* remote port */);

    EXPECT_TRUE(isOk(res)) << res;
    EXPECT_EQ(expectMsgLength, nlMsgBuf.size());

    Slice nlMsgSlice = netdutils::makeSlice(nlMsgBuf);
    nlMsgSlice = drop(nlMsgSlice, NLMSG_HDRLEN);

    xfrm_usersa_info usersa{};
    netdutils::extract(nlMsgSlice, usersa);

    EXPECT_EQ(AF_INET, usersa.family);
    EXPECT_EQ(1 /* Transform Id*/, static_cast<int>(usersa.reqid));
    EXPECT_EQ(XFRM_MODE_TUNNEL, usersa.mode);
    EXPECT_EQ(htonl(DROID_SPI), usersa.id.spi);
    EXPECT_EQ(IPPROTO_ESP, usersa.id.proto);

    expectAddressEquals(AF_INET, "127.0.0.1", usersa.saddr);
    expectAddressEquals(AF_INET, "8.8.8.8", usersa.id.daddr);

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
        }
    };
    forEachNetlinkAttribute(attr_buf, attrHandler);

    // TODO: Use ContainerEq or ElementsAreArray to get better test failure messages.
    EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(cryptKey.data()),
                        reinterpret_cast<void*>(&encryptAlgo.key), KEY_LENGTH));
    EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(authKey.data()),
                        reinterpret_cast<void*>(&authAlgo.key), KEY_LENGTH));
}

TEST_F(XfrmControllerTest, TestIpSecApplyTransportModeTransform) {

    int optlen = 0;
    Policy policy{};
    // Need to cast from void* in order to "SaveArg" policy. Easier to invoke a
    // lambda than to write a gMock action.
    auto SavePolicy = [&policy](const void* value) {
        policy = *reinterpret_cast<const Policy*>(value);
    };

    XfrmController ctrl;

    struct sockaddr socketaddr;
    socketaddr.sa_family = AF_INET;

    unique_fd sock(socket(AF_INET, SOCK_STREAM, 0));

    EXPECT_CALL(mockSyscalls, getsockname(_, _, _))
        .WillOnce(DoAll(SetArgPointee<1>(socketaddr), Return(netdutils::status::ok)));

    EXPECT_CALL(mockSyscalls, setsockopt(_, _, _, _, _))
        .WillOnce(DoAll(WithArg<3>(Invoke(SavePolicy)), SaveArg<4>(&optlen),
                        Return(netdutils::status::ok)));

    Status res = ctrl.ipSecApplyTransportModeTransform(
        sock, 1 /* resourceId */, static_cast<int>(XfrmDirection::OUT),
        "127.0.0.1" /* local address */, "8.8.8.8" /* remote address */, DROID_SPI);

    EXPECT_TRUE(isOk(res)) << res;
    EXPECT_EQ(static_cast<int>(sizeof(Policy)), optlen);

    EXPECT_EQ(1 /* resourceId */, static_cast<int>(policy.tmpl.reqid));
    EXPECT_EQ(htonl(DROID_SPI), policy.tmpl.id.spi);

    expectAddressEquals(AF_INET, "127.0.0.1", policy.tmpl.saddr);
    expectAddressEquals(AF_INET, "8.8.8.8", policy.tmpl.id.daddr);
}

TEST_F(XfrmControllerTest, TestIpSecDeleteSecurityAssociation) {
    XfrmController ctrl;
    NetlinkResponse response = {};
    response.hdr.nlmsg_type = XFRM_MSG_ALLOCSPI;

    /** It's an injected return result for the sendMessage function to go through */
    StatusOr<Slice> readStatus(netdutils::makeSlice(response));

    size_t expectMsgLength = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(xfrm_usersa_id));
    // Set the return to allow the program run through
    StatusOr<size_t> expectRet(expectMsgLength);

    std::vector<uint8_t> nlMsgBuf;
    EXPECT_CALL(mockSyscalls, writev(_, _))
        .WillOnce(DoAll(SaveFlattenedIovecs<1>(&nlMsgBuf), Return(expectRet)));
    EXPECT_CALL(mockSyscalls, read(_, _))
        .WillOnce(DoAll(SetArgSlice<1>(netdutils::makeSlice(response)), Return(readStatus)));

    Status res = ctrl.ipSecDeleteSecurityAssociation(
        1 /* resourceId */, static_cast<int>(XfrmDirection::OUT), "127.0.0.1" /* local address */,
        "8.8.8.8" /* remote address */, DROID_SPI);

    EXPECT_TRUE(isOk(res)) << res;
    EXPECT_EQ(expectMsgLength, nlMsgBuf.size());

    Slice nlMsgSlice = netdutils::makeSlice(nlMsgBuf);
    nlMsgSlice = netdutils::drop(nlMsgSlice, NLMSG_HDRLEN);

    xfrm_usersa_id said{};
    netdutils::extract(nlMsgSlice, said);

    EXPECT_EQ(htonl(DROID_SPI), said.spi);

    expectAddressEquals(AF_INET, "8.8.8.8", said.daddr);
}

} // namespace net
} // namespace android
