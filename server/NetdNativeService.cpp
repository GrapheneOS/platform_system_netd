/**
 * Copyright (c) 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "Netd"

#include <cinttypes>
#include <set>
#include <tuple>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/properties.h>
#include <log/log.h>
#include <utils/Errors.h>
#include <utils/String16.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include "android/net/BnNetd.h"

#include <openssl/base64.h>

#include "Controllers.h"
#include "DumpWriter.h"
#include "InterfaceController.h"
#include "NetdConstants.h"  // SHA256_SIZE
#include "NetdNativeService.h"
#include "Permission.h"
#include "Process.h"
#include "RouteController.h"
#include "SockDiag.h"
#include "UidRanges.h"
#include "netid_client.h"  // NETID_UNSET

using android::base::StringPrintf;
using android::base::WriteStringToFile;
using android::net::TetherStatsParcel;
using android::net::UidRangeParcel;
using android::os::ParcelFileDescriptor;

namespace android {
namespace net {

namespace {

const char CONNECTIVITY_INTERNAL[] = "android.permission.CONNECTIVITY_INTERNAL";
const char NETWORK_STACK[] = "android.permission.NETWORK_STACK";
const char DUMP[] = "android.permission.DUMP";
const char OPT_SHORT[] = "--short";

binder::Status checkPermission(const char *permission) {
    pid_t pid = IPCThreadState::self()->getCallingPid();
    uid_t uid = IPCThreadState::self()->getCallingUid();

    // If the caller is the system UID, don't check permissions.
    // Otherwise, if the system server's binder thread pool is full, and all the threads are
    // blocked on a thread that's waiting for us to complete, we deadlock. http://b/69389492
    //
    // From a security perspective, there is currently no difference, because:
    // 1. The only permissions we check in netd's binder interface are CONNECTIVITY_INTERNAL
    //    and NETWORK_STACK, which the system server will always need to have.
    // 2. AID_SYSTEM always has all permissions. See ActivityManager#checkComponentPermission.
    if (uid == AID_SYSTEM || checkPermission(String16(permission), pid, uid)) {
        return binder::Status::ok();
    } else {
        auto err = StringPrintf("UID %d / PID %d lacks permission %s", uid, pid, permission);
        return binder::Status::fromExceptionCode(binder::Status::EX_SECURITY, String8(err.c_str()));
    }
}

#define ENFORCE_DEBUGGABLE() {                              \
    char value[PROPERTY_VALUE_MAX + 1];                     \
    if (property_get("ro.debuggable", value, nullptr) != 1  \
            || value[0] != '1') {                           \
        return binder::Status::fromExceptionCode(           \
            binder::Status::EX_SECURITY,                    \
            String8("Not available in production builds.")  \
        );                                                  \
    }                                                       \
}

#define ENFORCE_PERMISSION(permission) {                    \
    binder::Status status = checkPermission((permission));  \
    if (!status.isOk()) {                                   \
        return status;                                      \
    }                                                       \
}

#define NETD_LOCKING_RPC(permission, lock)                  \
    ENFORCE_PERMISSION(permission);                         \
    std::lock_guard _lock(lock);

#define NETD_BIG_LOCK_RPC(permission) NETD_LOCKING_RPC((permission), gBigNetdLock)

#define RETURN_BINDER_STATUS_IF_NOT_OK(logEntry, res) \
    do {                                              \
        if (!isOk((res))) {                           \
            logErrorStatus((logEntry), (res));        \
            return asBinderStatus((res));             \
        }                                             \
    } while (0)

void logErrorStatus(netdutils::LogEntry& logEntry, const netdutils::Status& status) {
    gLog.log(logEntry.returns(status.code()).withAutomaticDuration());
}

binder::Status asBinderStatus(const netdutils::Status& status) {
    if (isOk(status)) {
        return binder::Status::ok();
    }
    return binder::Status::fromServiceSpecificError(status.code(), status.msg().c_str());
}

inline binder::Status statusFromErrcode(int ret) {
    if (ret) {
        return binder::Status::fromServiceSpecificError(-ret, strerror(-ret));
    }
    return binder::Status::ok();
}

bool contains(const Vector<String16>& words, const String16& word) {
    for (const auto& w : words) {
        if (w == word) return true;
    }

    return false;
}

}  // namespace

status_t NetdNativeService::start() {
    IPCThreadState::self()->disableBackgroundScheduling(true);
    const status_t ret = BinderService<NetdNativeService>::publish();
    if (ret != android::OK) {
        return ret;
    }
    sp<ProcessState> ps(ProcessState::self());
    ps->startThreadPool();
    ps->giveThreadPoolName();
    return android::OK;
}

status_t NetdNativeService::dump(int fd, const Vector<String16> &args) {
    const binder::Status dump_permission = checkPermission(DUMP);
    if (!dump_permission.isOk()) {
        const String8 msg(dump_permission.toString8());
        write(fd, msg.string(), msg.size());
        return PERMISSION_DENIED;
    }

    // This method does not grab any locks. If individual classes need locking
    // their dump() methods MUST handle locking appropriately.

    DumpWriter dw(fd);

    if (!args.isEmpty() && args[0] == TcpSocketMonitor::DUMP_KEYWORD) {
      dw.blankline();
      gCtls->tcpSocketMonitor.dump(dw);
      dw.blankline();
      return NO_ERROR;
    }

    if (!args.isEmpty() && args[0] == TrafficController::DUMP_KEYWORD) {
        dw.blankline();
        gCtls->trafficCtrl.dump(dw, true);
        dw.blankline();
        return NO_ERROR;
    }

    process::dump(dw);
    dw.blankline();
    gCtls->netCtrl.dump(dw);
    dw.blankline();

    gCtls->trafficCtrl.dump(dw, false);
    dw.blankline();

    gCtls->xfrmCtrl.dump(dw);
    dw.blankline();

    {
        ScopedIndent indentLog(dw);
        if (contains(args, String16(OPT_SHORT))) {
            dw.println("Log: <omitted>");
        } else {
            dw.println("Log:");
            ScopedIndent indentLogEntries(dw);
            gLog.forEachEntry([&dw](const std::string& entry) mutable { dw.println(entry); });
        }
        dw.blankline();
    }

    {
        ScopedIndent indentLog(dw);
        if (contains(args, String16(OPT_SHORT))) {
            dw.println("UnsolicitedLog: <omitted>");
        } else {
            dw.println("UnsolicitedLog:");
            ScopedIndent indentLogEntries(dw);
            gUnsolicitedLog.forEachEntry(
                    [&dw](const std::string& entry) mutable { dw.println(entry); });
        }
        dw.blankline();
    }

    return NO_ERROR;
}

binder::Status NetdNativeService::isAlive(bool *alive) {
    NETD_BIG_LOCK_RPC(CONNECTIVITY_INTERNAL);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);

    *alive = true;

    gLog.log(entry.returns(*alive));
    return binder::Status::ok();
}

binder::Status NetdNativeService::firewallReplaceUidChain(const std::string& chainName,
        bool isWhitelist, const std::vector<int32_t>& uids, bool *ret) {
    NETD_LOCKING_RPC(CONNECTIVITY_INTERNAL, gCtls->firewallCtrl.lock);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(chainName)
                         .arg(isWhitelist)
                         .arg(uids);

    int err = gCtls->firewallCtrl.replaceUidChain(chainName, isWhitelist, uids);
    *ret = (err == 0);

    gLog.log(entry.returns(*ret).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::bandwidthEnableDataSaver(bool enable, bool *ret) {
    NETD_LOCKING_RPC(CONNECTIVITY_INTERNAL, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(enable);

    int err = gCtls->bandwidthCtrl.enableDataSaver(enable);
    *ret = (err == 0);
    gLog.log(entry.returns(*ret).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::bandwidthSetInterfaceQuota(const std::string& ifName,
                                                             int64_t bytes) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName).arg(bytes);

    int res = gCtls->bandwidthCtrl.setInterfaceQuota(ifName, bytes);

    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::bandwidthRemoveInterfaceQuota(const std::string& ifName) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName);

    int res = gCtls->bandwidthCtrl.removeInterfaceQuota(ifName);

    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::bandwidthSetInterfaceAlert(const std::string& ifName,
                                                             int64_t bytes) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName).arg(bytes);

    int res = gCtls->bandwidthCtrl.setInterfaceAlert(ifName, bytes);

    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::bandwidthRemoveInterfaceAlert(const std::string& ifName) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName);

    int res = gCtls->bandwidthCtrl.removeInterfaceAlert(ifName);

    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::bandwidthSetGlobalAlert(int64_t bytes) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(bytes);

    int res = gCtls->bandwidthCtrl.setGlobalAlert(bytes);

    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::bandwidthAddNaughtyApp(int32_t uid) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(uid);

    std::vector<std::string> appStrUids = {std::to_string(abs(uid))};
    int res = gCtls->bandwidthCtrl.addNaughtyApps(appStrUids);

    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::bandwidthRemoveNaughtyApp(int32_t uid) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(uid);

    std::vector<std::string> appStrUids = {std::to_string(abs(uid))};
    int res = gCtls->bandwidthCtrl.removeNaughtyApps(appStrUids);

    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::bandwidthAddNiceApp(int32_t uid) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(uid);

    std::vector<std::string> appStrUids = {std::to_string(abs(uid))};
    int res = gCtls->bandwidthCtrl.addNiceApps(appStrUids);

    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::bandwidthRemoveNiceApp(int32_t uid) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->bandwidthCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(uid);

    std::vector<std::string> appStrUids = {std::to_string(abs(uid))};
    int res = gCtls->bandwidthCtrl.removeNiceApps(appStrUids);

    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::networkCreatePhysical(int32_t netId, int32_t permission) {
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(netId).arg(permission);
    int ret = gCtls->netCtrl.createPhysicalNetwork(netId, convertPermission(permission));
    gLog.log(entry.returns(ret).withAutomaticDuration());
    return statusFromErrcode(ret);
}

binder::Status NetdNativeService::networkCreateVpn(int32_t netId, bool secure) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).args(netId, secure);
    int ret = gCtls->netCtrl.createVirtualNetwork(netId, secure);
    gLog.log(entry.returns(ret).withAutomaticDuration());
    return statusFromErrcode(ret);
}

binder::Status NetdNativeService::networkDestroy(int32_t netId) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    // Both of these functions manage their own locking internally.
    const int ret = gCtls->netCtrl.destroyNetwork(netId);
    gCtls->resolverCtrl.clearDnsServers(netId);
    return statusFromErrcode(ret);
}

binder::Status NetdNativeService::networkAddInterface(int32_t netId, const std::string& iface) {
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    int ret = gCtls->netCtrl.addInterfaceToNetwork(netId, iface.c_str());
    return statusFromErrcode(ret);
}

binder::Status NetdNativeService::networkRemoveInterface(int32_t netId, const std::string& iface) {
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    int ret = gCtls->netCtrl.removeInterfaceFromNetwork(netId, iface.c_str());
    return statusFromErrcode(ret);
}

namespace {

std::string uidRangeParcelVecToString(const std::vector<UidRangeParcel>& uidRangeArray) {
    std::vector<std::string> result;
    result.reserve(uidRangeArray.size());
    for (const auto& uidRange : uidRangeArray) {
        result.push_back(StringPrintf("%d-%d", uidRange.start, uidRange.stop));
    }

    return base::Join(result, ", ");
}

}  // namespace

binder::Status NetdNativeService::networkAddUidRanges(
        int32_t netId, const std::vector<UidRangeParcel>& uidRangeArray) {
    // NetworkController::addUsersToNetwork is thread-safe.
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .args(netId, uidRangeParcelVecToString(uidRangeArray));

    int ret = gCtls->netCtrl.addUsersToNetwork(netId, UidRanges(uidRangeArray));
    gLog.log(entry.returns(ret).withAutomaticDuration());
    return statusFromErrcode(ret);
}

binder::Status NetdNativeService::networkRemoveUidRanges(
        int32_t netId, const std::vector<UidRangeParcel>& uidRangeArray) {
    // NetworkController::removeUsersFromNetwork is thread-safe.
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .args(netId, uidRangeParcelVecToString(uidRangeArray));

    int ret = gCtls->netCtrl.removeUsersFromNetwork(netId, UidRanges(uidRangeArray));
    gLog.log(entry.returns(ret).withAutomaticDuration());
    return statusFromErrcode(ret);
}

binder::Status NetdNativeService::networkRejectNonSecureVpn(
        bool add, const std::vector<UidRangeParcel>& uidRangeArray) {
    // TODO: elsewhere RouteController is only used from the tethering and network controllers, so
    // it should be possible to use the same lock as NetworkController. However, every call through
    // the CommandListener "network" command will need to hold this lock too, not just the ones that
    // read/modify network internal state (that is sufficient for ::dump() because it doesn't
    // look at routes, but it's not enough here).
    NETD_BIG_LOCK_RPC(CONNECTIVITY_INTERNAL);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .args(add, uidRangeParcelVecToString(uidRangeArray));
    UidRanges uidRanges(uidRangeArray);

    int err;
    if (add) {
        err = RouteController::addUsersToRejectNonSecureNetworkRule(uidRanges);
    } else {
        err = RouteController::removeUsersFromRejectNonSecureNetworkRule(uidRanges);
    }
    gLog.log(entry.returns(err).withAutomaticDuration());
    return statusFromErrcode(err);
}

binder::Status NetdNativeService::socketDestroy(const std::vector<UidRangeParcel>& uids,
                                                const std::vector<int32_t>& skipUids) {
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);

    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(uidRangeParcelVecToString(uids));
    SockDiag sd;
    if (!sd.open()) {
        return binder::Status::fromServiceSpecificError(EIO,
                String8("Could not open SOCK_DIAG socket"));
    }

    UidRanges uidRanges(uids);
    int err = sd.destroySockets(uidRanges, std::set<uid_t>(skipUids.begin(), skipUids.end()),
                                true /* excludeLoopback */);

    gLog.log(entry.returns(err).withAutomaticDuration());
    if (err) {
        return binder::Status::fromServiceSpecificError(-err,
                String8::format("destroySockets: %s", strerror(-err)));
    }
    return binder::Status::ok();
}

// Parse a base64 encoded string into a vector of bytes.
// On failure, return an empty vector.
static std::vector<uint8_t> parseBase64(const std::string& input) {
    std::vector<uint8_t> decoded;
    size_t out_len;
    if (EVP_DecodedLength(&out_len, input.size()) != 1) {
        return decoded;
    }
    // out_len is now an upper bound on the output length.
    decoded.resize(out_len);
    if (EVP_DecodeBase64(decoded.data(), &out_len, decoded.size(),
            reinterpret_cast<const uint8_t*>(input.data()), input.size()) == 1) {
        // Possibly shrink the vector if the actual output was smaller than the bound.
        decoded.resize(out_len);
    } else {
        decoded.clear();
    }
    if (out_len != SHA256_SIZE) {
        decoded.clear();
    }
    return decoded;
}

binder::Status NetdNativeService::setResolverConfiguration(int32_t netId,
        const std::vector<std::string>& servers, const std::vector<std::string>& domains,
        const std::vector<int32_t>& params, const std::string& tlsName,
        const std::vector<std::string>& tlsServers,
        const std::vector<std::string>& tlsFingerprints) {
    // This function intentionally does not lock within Netd, as Bionic is thread-safe.
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(netId)
                         .arg(servers)
                         .arg(domains)
                         .arg(params)
                         .arg(tlsName)
                         .arg(tlsServers)
                         .arg(tlsFingerprints);

    std::set<std::vector<uint8_t>> decoded_fingerprints;
    for (const std::string& fingerprint : tlsFingerprints) {
        std::vector<uint8_t> decoded = parseBase64(fingerprint);
        if (decoded.empty()) {
            return binder::Status::fromServiceSpecificError(EINVAL,
                    String8::format("ResolverController error: bad fingerprint"));
        }
        decoded_fingerprints.emplace(decoded);
    }

    int err = gCtls->resolverCtrl.setResolverConfiguration(netId, servers, domains, params,
            tlsName, tlsServers, decoded_fingerprints);
    gLog.log(entry.returns(err).withAutomaticDuration());
    if (err != 0) {
        return binder::Status::fromServiceSpecificError(-err,
                String8::format("ResolverController error: %s", strerror(-err)));
    }
    return binder::Status::ok();
}

binder::Status NetdNativeService::getResolverInfo(int32_t netId, std::vector<std::string>* servers,
                                                  std::vector<std::string>* domains,
                                                  std::vector<std::string>* tlsServers,
                                                  std::vector<int32_t>* params,
                                                  std::vector<int32_t>* stats) {
    // This function intentionally does not lock within Netd, as Bionic is thread-safe.
    ENFORCE_PERMISSION(NETWORK_STACK);

    int err =
            gCtls->resolverCtrl.getResolverInfo(netId, servers, domains, tlsServers, params, stats);
    if (err != 0) {
        return binder::Status::fromServiceSpecificError(-err,
                String8::format("ResolverController error: %s", strerror(-err)));
    }
    return binder::Status::ok();
}

binder::Status NetdNativeService::tetherApplyDnsInterfaces(bool *ret) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);

    *ret = gCtls->tetherCtrl.applyDnsInterfaces();
    return binder::Status::ok();
}

namespace {

void tetherAddStatsByInterface(TetherController::TetherStats* tetherStatsParcel,
                               const TetherController::TetherStats& tetherStats) {
    if (tetherStatsParcel->extIface == tetherStats.extIface) {
        tetherStatsParcel->rxBytes += tetherStats.rxBytes;
        tetherStatsParcel->rxPackets += tetherStats.rxPackets;
        tetherStatsParcel->txBytes += tetherStats.txBytes;
        tetherStatsParcel->txPackets += tetherStats.txPackets;
    }
}

TetherStatsParcel toTetherStatsParcel(const TetherController::TetherStats& stats) {
    TetherStatsParcel result;
    result.iface = stats.extIface;
    result.rxBytes = stats.rxBytes;
    result.rxPackets = stats.rxPackets;
    result.txBytes = stats.txBytes;
    result.txPackets = stats.txPackets;
    return result;
}

void setTetherStatsParcelVecByInterface(std::vector<TetherStatsParcel>* tetherStatsVec,
                                        const TetherController::TetherStatsList& statsList) {
    std::map<std::string, TetherController::TetherStats> statsMap;
    for (const auto& stats : statsList) {
        auto iter = statsMap.find(stats.extIface);
        if (iter != statsMap.end()) {
            tetherAddStatsByInterface(&(iter->second), stats);
        } else {
            statsMap.insert(
                    std::pair<std::string, TetherController::TetherStats>(stats.extIface, stats));
        }
    }
    for (auto iter = statsMap.begin(); iter != statsMap.end(); iter++) {
        tetherStatsVec->push_back(toTetherStatsParcel(iter->second));
    }
}

std::vector<std::string> tetherStatsParcelVecToStringVec(std::vector<TetherStatsParcel>* tVec) {
    std::vector<std::string> result;
    for (const auto& t : *tVec) {
        result.push_back(StringPrintf("%s:%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64,
                                      t.iface.c_str(), t.rxBytes, t.rxPackets, t.txBytes,
                                      t.txPackets));
    }
    return result;
}

}  // namespace

binder::Status NetdNativeService::tetherGetStats(
        std::vector<TetherStatsParcel>* tetherStatsParcelVec) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);

    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);

    const auto& statsList = gCtls->tetherCtrl.getTetherStats();
    if (!isOk(statsList)) {
        return asBinderStatus(statsList);
    }
    setTetherStatsParcelVecByInterface(tetherStatsParcelVec, statsList.value());
    auto statsResults = tetherStatsParcelVecToStringVec(tetherStatsParcelVec);
    gLog.log(entry.returns(base::Join(statsResults, ";")).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::interfaceAddAddress(const std::string &ifName,
        const std::string &addrString, int prefixLength) {
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);

    const int err = InterfaceController::addAddress(
            ifName.c_str(), addrString.c_str(), prefixLength);
    if (err != 0) {
        return binder::Status::fromServiceSpecificError(-err,
                String8::format("InterfaceController error: %s", strerror(-err)));
    }
    return binder::Status::ok();
}

binder::Status NetdNativeService::interfaceDelAddress(const std::string &ifName,
        const std::string &addrString, int prefixLength) {
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);

    const int err = InterfaceController::delAddress(
            ifName.c_str(), addrString.c_str(), prefixLength);
    if (err != 0) {
        return binder::Status::fromServiceSpecificError(-err,
                String8::format("InterfaceController error: %s", strerror(-err)));
    }
    return binder::Status::ok();
}

namespace {

std::tuple<binder::Status, const char*, const char*> getPathComponents(int32_t ipversion,
                                                                       int32_t category) {
    const char* ipversionStr = nullptr;
    switch (ipversion) {
        case INetd::IPV4:
            ipversionStr = "ipv4";
            break;
        case INetd::IPV6:
            ipversionStr = "ipv6";
            break;
        default:
            return {binder::Status::fromServiceSpecificError(EAFNOSUPPORT, "Bad IP version"),
                    nullptr, nullptr};
    }

    const char* whichStr = nullptr;
    switch (category) {
        case INetd::CONF:
            whichStr = "conf";
            break;
        case INetd::NEIGH:
            whichStr = "neigh";
            break;
        default:
            return {binder::Status::fromServiceSpecificError(EINVAL, "Bad category"), nullptr,
                    nullptr};
    }

    return {binder::Status::ok(), ipversionStr, whichStr};
}

}  // namespace

binder::Status NetdNativeService::getProcSysNet(int32_t ipversion, int32_t which,
                                                const std::string& ifname,
                                                const std::string& parameter, std::string* value) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__)
                         .args(ipversion, which, ifname, parameter);

    const auto pathParts = getPathComponents(ipversion, which);
    const auto& pathStatus = std::get<0>(pathParts);
    if (!pathStatus.isOk()) {
        gLog.log(entry.returns(pathStatus.exceptionCode()).withAutomaticDuration());
        return pathStatus;
    }

    const int err = InterfaceController::getParameter(std::get<1>(pathParts),
                                                      std::get<2>(pathParts), ifname.c_str(),
                                                      parameter.c_str(), value);
    entry.returns(err);
    if (err == 0) entry.returns(*value);
    gLog.log(entry.withAutomaticDuration());
    return statusFromErrcode(err);
}

binder::Status NetdNativeService::setProcSysNet(int32_t ipversion, int32_t which,
                                                const std::string& ifname,
                                                const std::string& parameter,
                                                const std::string& value) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__)
                         .args(ipversion, which, ifname, parameter, value);

    const auto pathParts = getPathComponents(ipversion, which);
    const auto& pathStatus = std::get<0>(pathParts);
    if (!pathStatus.isOk()) {
        gLog.log(entry.returns(pathStatus.exceptionCode()).withAutomaticDuration());
        return pathStatus;
    }

    const int err = InterfaceController::setParameter(std::get<1>(pathParts),
                                                      std::get<2>(pathParts), ifname.c_str(),
                                                      parameter.c_str(), value.c_str());
    gLog.log(entry.returns(err).withAutomaticDuration());
    return statusFromErrcode(err);
}

binder::Status NetdNativeService::ipSecSetEncapSocketOwner(const ParcelFileDescriptor& socket,
                                                           int newUid) {
    ENFORCE_PERMISSION(NETWORK_STACK)
    gLog.log("ipSecSetEncapSocketOwner()");

    uid_t callerUid = IPCThreadState::self()->getCallingUid();
    return asBinderStatus(
            gCtls->xfrmCtrl.ipSecSetEncapSocketOwner(socket.get(), newUid, callerUid));
}

binder::Status NetdNativeService::ipSecAllocateSpi(
        int32_t transformId,
        const std::string& sourceAddress,
        const std::string& destinationAddress,
        int32_t inSpi,
        int32_t* outSpi) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    gLog.log("ipSecAllocateSpi()");
    return asBinderStatus(gCtls->xfrmCtrl.ipSecAllocateSpi(
                    transformId,
                    sourceAddress,
                    destinationAddress,
                    inSpi,
                    outSpi));
}

binder::Status NetdNativeService::ipSecAddSecurityAssociation(
        int32_t transformId, int32_t mode, const std::string& sourceAddress,
        const std::string& destinationAddress, int32_t underlyingNetId, int32_t spi,
        int32_t markValue, int32_t markMask, const std::string& authAlgo,
        const std::vector<uint8_t>& authKey, int32_t authTruncBits, const std::string& cryptAlgo,
        const std::vector<uint8_t>& cryptKey, int32_t cryptTruncBits, const std::string& aeadAlgo,
        const std::vector<uint8_t>& aeadKey, int32_t aeadIcvBits, int32_t encapType,
        int32_t encapLocalPort, int32_t encapRemotePort, int32_t interfaceId) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    gLog.log("ipSecAddSecurityAssociation()");
    return asBinderStatus(gCtls->xfrmCtrl.ipSecAddSecurityAssociation(
            transformId, mode, sourceAddress, destinationAddress, underlyingNetId, spi, markValue,
            markMask, authAlgo, authKey, authTruncBits, cryptAlgo, cryptKey, cryptTruncBits,
            aeadAlgo, aeadKey, aeadIcvBits, encapType, encapLocalPort, encapRemotePort,
            interfaceId));
}

binder::Status NetdNativeService::ipSecDeleteSecurityAssociation(
        int32_t transformId, const std::string& sourceAddress,
        const std::string& destinationAddress, int32_t spi, int32_t markValue, int32_t markMask,
        int32_t interfaceId) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    gLog.log("ipSecDeleteSecurityAssociation()");
    return asBinderStatus(gCtls->xfrmCtrl.ipSecDeleteSecurityAssociation(
            transformId, sourceAddress, destinationAddress, spi, markValue, markMask, interfaceId));
}

binder::Status NetdNativeService::ipSecApplyTransportModeTransform(
        const ParcelFileDescriptor& socket, int32_t transformId, int32_t direction,
        const std::string& sourceAddress, const std::string& destinationAddress, int32_t spi) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    gLog.log("ipSecApplyTransportModeTransform()");
    return asBinderStatus(gCtls->xfrmCtrl.ipSecApplyTransportModeTransform(
            socket.get(), transformId, direction, sourceAddress, destinationAddress, spi));
}

binder::Status NetdNativeService::ipSecRemoveTransportModeTransform(
        const ParcelFileDescriptor& socket) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(CONNECTIVITY_INTERNAL);
    gLog.log("ipSecRemoveTransportModeTransform()");
    return asBinderStatus(gCtls->xfrmCtrl.ipSecRemoveTransportModeTransform(socket.get()));
}

binder::Status NetdNativeService::ipSecAddSecurityPolicy(int32_t transformId, int32_t selAddrFamily,
                                                         int32_t direction,
                                                         const std::string& tmplSrcAddress,
                                                         const std::string& tmplDstAddress,
                                                         int32_t spi, int32_t markValue,
                                                         int32_t markMask, int32_t interfaceId) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(NETWORK_STACK);
    gLog.log("ipSecAddSecurityPolicy()");
    return asBinderStatus(gCtls->xfrmCtrl.ipSecAddSecurityPolicy(
            transformId, selAddrFamily, direction, tmplSrcAddress, tmplDstAddress, spi, markValue,
            markMask, interfaceId));
}

binder::Status NetdNativeService::ipSecUpdateSecurityPolicy(
        int32_t transformId, int32_t selAddrFamily, int32_t direction,
        const std::string& tmplSrcAddress, const std::string& tmplDstAddress, int32_t spi,
        int32_t markValue, int32_t markMask, int32_t interfaceId) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(NETWORK_STACK);
    gLog.log("ipSecAddSecurityPolicy()");
    return asBinderStatus(gCtls->xfrmCtrl.ipSecUpdateSecurityPolicy(
            transformId, selAddrFamily, direction, tmplSrcAddress, tmplDstAddress, spi, markValue,
            markMask, interfaceId));
}

binder::Status NetdNativeService::ipSecDeleteSecurityPolicy(int32_t transformId,
                                                            int32_t selAddrFamily,
                                                            int32_t direction, int32_t markValue,
                                                            int32_t markMask, int32_t interfaceId) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(NETWORK_STACK);
    gLog.log("ipSecAddSecurityPolicy()");
    return asBinderStatus(gCtls->xfrmCtrl.ipSecDeleteSecurityPolicy(
            transformId, selAddrFamily, direction, markValue, markMask, interfaceId));
}

binder::Status NetdNativeService::ipSecAddTunnelInterface(const std::string& deviceName,
                                                          const std::string& localAddress,
                                                          const std::string& remoteAddress,
                                                          int32_t iKey, int32_t oKey,
                                                          int32_t interfaceId) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);

    netdutils::Status result = gCtls->xfrmCtrl.ipSecAddTunnelInterface(
            deviceName, localAddress, remoteAddress, iKey, oKey, interfaceId, false);
    RETURN_BINDER_STATUS_IF_NOT_OK(entry, result);

    gLog.log(entry.returns(result).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::ipSecUpdateTunnelInterface(const std::string& deviceName,
                                                             const std::string& localAddress,
                                                             const std::string& remoteAddress,
                                                             int32_t iKey, int32_t oKey,
                                                             int32_t interfaceId) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);

    netdutils::Status result = gCtls->xfrmCtrl.ipSecAddTunnelInterface(
            deviceName, localAddress, remoteAddress, iKey, oKey, interfaceId, true);
    RETURN_BINDER_STATUS_IF_NOT_OK(entry, result);

    gLog.log(entry.returns(result).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::ipSecRemoveTunnelInterface(const std::string& deviceName) {
    // Necessary locking done in IpSecService and kernel
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);

    netdutils::Status result = gCtls->xfrmCtrl.ipSecRemoveTunnelInterface(deviceName);
    RETURN_BINDER_STATUS_IF_NOT_OK(entry, result);

    gLog.log(entry.returns(result).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::setIPv6AddrGenMode(const std::string& ifName,
                                                     int32_t mode) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    return asBinderStatus(InterfaceController::setIPv6AddrGenMode(ifName, mode));
}

binder::Status NetdNativeService::wakeupAddInterface(const std::string& ifName,
                                                     const std::string& prefix, int32_t mark,
                                                     int32_t mask) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    return asBinderStatus(gCtls->wakeupCtrl.addInterface(ifName, prefix, mark, mask));
}

binder::Status NetdNativeService::wakeupDelInterface(const std::string& ifName,
                                                     const std::string& prefix, int32_t mark,
                                                     int32_t mask) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    return asBinderStatus(gCtls->wakeupCtrl.delInterface(ifName, prefix, mark, mask));
}

binder::Status NetdNativeService::trafficCheckBpfStatsEnable(bool* ret) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    *ret = gCtls->trafficCtrl.checkBpfStatsEnable();
    return binder::Status::ok();
}

binder::Status NetdNativeService::idletimerAddInterface(const std::string& ifName, int32_t timeout,
                                                        const std::string& classLabel) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->idletimerCtrl.lock);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(ifName)
                         .arg(timeout)
                         .arg(classLabel);
    int res =
            gCtls->idletimerCtrl.addInterfaceIdletimer(ifName.c_str(), timeout, classLabel.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::idletimerRemoveInterface(const std::string& ifName,
                                                           int32_t timeout,
                                                           const std::string& classLabel) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->idletimerCtrl.lock);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(ifName)
                         .arg(timeout)
                         .arg(classLabel);
    int res = gCtls->idletimerCtrl.removeInterfaceIdletimer(ifName.c_str(), timeout,
                                                            classLabel.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::strictUidCleartextPenalty(int32_t uid, int32_t policyPenalty) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->strictCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(uid).arg(policyPenalty);
    StrictPenalty penalty;
    switch (policyPenalty) {
        case INetd::PENALTY_POLICY_REJECT:
            penalty = REJECT;
            break;
        case INetd::PENALTY_POLICY_LOG:
            penalty = LOG;
            break;
        case INetd::PENALTY_POLICY_ACCEPT:
            penalty = ACCEPT;
            break;
        default:
            return statusFromErrcode(-EINVAL);
            break;
    }
    int res = gCtls->strictCtrl.setUidCleartextPenalty((uid_t) uid, penalty);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::clatdStart(const std::string& ifName) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->clatdCtrl.mutex);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName);
    int res = gCtls->clatdCtrl.startClatd(ifName.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::clatdStop(const std::string& ifName) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->clatdCtrl.mutex);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName);
    int res = gCtls->clatdCtrl.stopClatd(ifName.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::ipfwdEnabled(bool* status) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);
    *status = (gCtls->tetherCtrl.forwardingRequestCount() > 0) ? true : false;
    gLog.log(entry.returns(*status).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::ipfwdEnableForwarding(const std::string& requester) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(requester);
    int res = (gCtls->tetherCtrl.enableForwarding(requester.c_str())) ? 0 : -EREMOTEIO;
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::ipfwdDisableForwarding(const std::string& requester) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(requester);
    int res = (gCtls->tetherCtrl.disableForwarding(requester.c_str())) ? 0 : -EREMOTEIO;
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::ipfwdAddInterfaceForward(const std::string& fromIface,
                                                           const std::string& toIface) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(fromIface).arg(toIface);
    int res = RouteController::enableTethering(fromIface.c_str(), toIface.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::ipfwdRemoveInterfaceForward(const std::string& fromIface,
                                                              const std::string& toIface) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(fromIface).arg(toIface);
    int res = RouteController::disableTethering(fromIface.c_str(), toIface.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

namespace {
std::string addSquareBrackets(const std::string& s) {
    return "[" + s + "]";
}

std::string addCurlyBrackets(const std::string& s) {
    return "{" + s + "}";
}

}  // namespace
binder::Status NetdNativeService::interfaceGetList(std::vector<std::string>* interfaceListResult) {
    NETD_LOCKING_RPC(NETWORK_STACK, InterfaceController::mutex);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);

    const auto& ifaceList = InterfaceController::getIfaceNames();
    RETURN_BINDER_STATUS_IF_NOT_OK(entry, ifaceList);

    interfaceListResult->clear();
    interfaceListResult->reserve(ifaceList.value().size());
    interfaceListResult->insert(end(*interfaceListResult), begin(ifaceList.value()),
                                end(ifaceList.value()));

    gLog.log(entry.returns(addSquareBrackets(base::Join(*interfaceListResult, ", ")))
                     .withAutomaticDuration());
    return binder::Status::ok();
}

std::string interfaceConfigurationParcelToString(const InterfaceConfigurationParcel& cfg) {
    std::vector<std::string> result{cfg.ifName, cfg.hwAddr, cfg.ipv4Addr,
                                    std::to_string(cfg.prefixLength)};
    result.insert(end(result), begin(cfg.flags), end(cfg.flags));
    return addCurlyBrackets(base::Join(result, ", "));
}

binder::Status NetdNativeService::interfaceGetCfg(
        const std::string& ifName, InterfaceConfigurationParcel* interfaceGetCfgResult) {
    NETD_LOCKING_RPC(NETWORK_STACK, InterfaceController::mutex);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName);

    const auto& cfgRes = InterfaceController::getCfg(ifName);
    RETURN_BINDER_STATUS_IF_NOT_OK(entry, cfgRes);

    *interfaceGetCfgResult = cfgRes.value();
    gLog.log(entry.returns(interfaceConfigurationParcelToString(*interfaceGetCfgResult))
                     .withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::interfaceSetCfg(const InterfaceConfigurationParcel& cfg) {
    NETD_LOCKING_RPC(NETWORK_STACK, InterfaceController::mutex);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(interfaceConfigurationParcelToString(cfg));

    const auto& res = InterfaceController::setCfg(cfg);
    RETURN_BINDER_STATUS_IF_NOT_OK(entry, res);

    gLog.log(entry.withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::interfaceSetIPv6PrivacyExtensions(const std::string& ifName,
                                                                    bool enable) {
    NETD_LOCKING_RPC(NETWORK_STACK, InterfaceController::mutex);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).args(ifName, enable);
    int res = InterfaceController::setIPv6PrivacyExtensions(ifName.c_str(), enable);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::interfaceClearAddrs(const std::string& ifName) {
    NETD_LOCKING_RPC(NETWORK_STACK, InterfaceController::mutex);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName);
    int res = InterfaceController::clearAddrs(ifName.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::interfaceSetEnableIPv6(const std::string& ifName, bool enable) {
    NETD_LOCKING_RPC(NETWORK_STACK, InterfaceController::mutex);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).args(ifName, enable);
    int res = InterfaceController::setEnableIPv6(ifName.c_str(), enable);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::interfaceSetMtu(const std::string& ifName, int32_t mtuValue) {
    NETD_LOCKING_RPC(NETWORK_STACK, InterfaceController::mutex);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).args(ifName, mtuValue);
    std::string mtu = std::to_string(mtuValue);
    int res = InterfaceController::setMtu(ifName.c_str(), mtu.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::tetherStart(const std::vector<std::string>& dhcpRanges) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(dhcpRanges);
    if (dhcpRanges.size() % 2 == 1) {
        return statusFromErrcode(-EINVAL);
    }
    int res = gCtls->tetherCtrl.startTethering(dhcpRanges);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::tetherStop() {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);
    int res = gCtls->tetherCtrl.stopTethering();
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::tetherIsEnabled(bool* enabled) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);
    *enabled = gCtls->tetherCtrl.isTetheringStarted();
    gLog.log(entry.returns(*enabled).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::tetherInterfaceAdd(const std::string& ifName) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName);
    int res = gCtls->tetherCtrl.tetherInterface(ifName.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::tetherInterfaceRemove(const std::string& ifName) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(ifName);
    int res = gCtls->tetherCtrl.untetherInterface(ifName.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::tetherInterfaceList(std::vector<std::string>* ifList) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);
    for (const auto& ifname : gCtls->tetherCtrl.getTetheredInterfaceList()) {
        ifList->push_back(ifname);
    }
    gLog.log(entry.returns(true).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::tetherDnsSet(int32_t netId,
                                               const std::vector<std::string>& dnsAddrs) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(netId).arg(dnsAddrs);
    int res = gCtls->tetherCtrl.setDnsForwarders(netId, dnsAddrs);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::tetherDnsList(std::vector<std::string>* dnsList) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);
    for (const auto& fwdr : gCtls->tetherCtrl.getDnsForwarders()) {
        dnsList->push_back(fwdr);
    }
    gLog.log(entry.returns(true).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::networkAddRoute(int32_t netId, const std::string& ifName,
                                                  const std::string& destination,
                                                  const std::string& nextHop) {
    // Public methods of NetworkController are thread-safe.
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(netId)
                         .arg(ifName)
                         .arg(destination)
                         .arg(nextHop);
    bool legacy = false;
    uid_t uid = 0;  // UID is only meaningful for legacy routes.
    int res = gCtls->netCtrl.addRoute(netId, ifName.c_str(), destination.c_str(),
                                      nextHop.empty() ? nullptr : nextHop.c_str(), legacy, uid);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::networkRemoveRoute(int32_t netId, const std::string& ifName,
                                                     const std::string& destination,
                                                     const std::string& nextHop) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(netId)
                         .arg(ifName)
                         .arg(destination)
                         .arg(nextHop);
    bool legacy = false;
    uid_t uid = 0;  // UID is only meaningful for legacy routes.
    int res = gCtls->netCtrl.removeRoute(netId, ifName.c_str(), destination.c_str(),
                                         nextHop.empty() ? nullptr : nextHop.c_str(), legacy, uid);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::networkAddLegacyRoute(int32_t netId, const std::string& ifName,
                                                        const std::string& destination,
                                                        const std::string& nextHop, int32_t uid) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(netId)
                         .arg(ifName)
                         .arg(destination)
                         .arg(nextHop)
                         .arg(uid);
    bool legacy = true;
    int res = gCtls->netCtrl.addRoute(netId, ifName.c_str(), destination.c_str(),
                                      nextHop.empty() ? nullptr : nextHop.c_str(), legacy,
                                      (uid_t) uid);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::networkRemoveLegacyRoute(int32_t netId, const std::string& ifName,
                                                           const std::string& destination,
                                                           const std::string& nextHop,
                                                           int32_t uid) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .arg(netId)
                         .arg(ifName)
                         .arg(destination)
                         .arg(nextHop)
                         .arg(uid);
    bool legacy = true;
    int res = gCtls->netCtrl.removeRoute(netId, ifName.c_str(), destination.c_str(),
                                         nextHop.empty() ? nullptr : nextHop.c_str(), legacy,
                                         (uid_t) uid);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::networkGetDefault(int32_t* netId) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);
    *netId = gCtls->netCtrl.getDefaultNetwork();
    gLog.log(entry.returns(*netId).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::networkSetDefault(int32_t netId) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(netId);
    int res = gCtls->netCtrl.setDefaultNetwork(netId);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::networkClearDefault() {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);
    unsigned netId = NETID_UNSET;
    int res = gCtls->netCtrl.setDefaultNetwork(netId);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

std::vector<uid_t> NetdNativeService::intsToUids(const std::vector<int32_t>& intUids) {
    return {begin(intUids), end(intUids)};
}

Permission NetdNativeService::convertPermission(int32_t permission) {
    switch (permission) {
        case INetd::PERMISSION_NETWORK:
            return Permission::PERMISSION_NETWORK;
        case INetd::PERMISSION_SYSTEM:
            return Permission::PERMISSION_SYSTEM;
        default:
            return Permission::PERMISSION_NONE;
    }
}

binder::Status NetdNativeService::networkSetPermissionForNetwork(int32_t netId,
                                                                 int32_t permission) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(netId).arg(permission);
    std::vector<unsigned> netIds = {(unsigned) netId};
    int res = gCtls->netCtrl.setPermissionForNetworks(convertPermission(permission), netIds);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::networkSetPermissionForUser(int32_t permission,
                                                              const std::vector<int32_t>& uids) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(permission).arg(uids);
    gCtls->netCtrl.setPermissionForUsers(convertPermission(permission), intsToUids(uids));
    gLog.log(entry.withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::networkClearPermissionForUser(const std::vector<int32_t>& uids) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(uids);
    Permission permission = Permission::PERMISSION_NONE;
    gCtls->netCtrl.setPermissionForUsers(permission, intsToUids(uids));
    gLog.log(entry.withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::NetdNativeService::networkSetProtectAllow(int32_t uid) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(uid);
    std::vector<uid_t> uids = {(uid_t) uid};
    gCtls->netCtrl.allowProtect(uids);
    gLog.log(entry.withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::networkSetProtectDeny(int32_t uid) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(uid);
    std::vector<uid_t> uids = {(uid_t) uid};
    gCtls->netCtrl.denyProtect(uids);
    gLog.log(entry.withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::networkCanProtect(int32_t uid, bool* ret) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(uid);
    *ret = gCtls->netCtrl.canProtect((uid_t) uid);
    gLog.log(entry.returns(*ret).withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::trafficSetNetPermForUids(int32_t permission,
                                                           const std::vector<int32_t>& uids) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(permission).arg(uids);
    gCtls->trafficCtrl.setPermissionForUids(permission, intsToUids(uids));
    gLog.log(entry.withAutomaticDuration());
    return binder::Status::ok();
}

namespace {
std::string ruleToString(int32_t rule) {
    switch (rule) {
        case INetd::FIREWALL_RULE_DENY:
            return "DENY";
        case INetd::FIREWALL_RULE_ALLOW:
            return "ALLOW";
        default:
            return "INVALID";
    }
}

std::string typeToString(int32_t type) {
    switch (type) {
        case INetd::FIREWALL_WHITELIST:
            return "WHITELIST";
        case INetd::FIREWALL_BLACKLIST:
            return "BLACKLIST";
        default:
            return "INVALID";
    }
}

std::string chainToString(int32_t chain) {
    switch (chain) {
        case INetd::FIREWALL_CHAIN_NONE:
            return "NONE";
        case INetd::FIREWALL_CHAIN_DOZABLE:
            return "DOZABLE";
        case INetd::FIREWALL_CHAIN_STANDBY:
            return "STANDBY";
        case INetd::FIREWALL_CHAIN_POWERSAVE:
            return "POWERSAVE";
        default:
            return "INVALID";
    }
}

}  // namespace

binder::Status NetdNativeService::firewallSetFirewallType(int32_t firewallType) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->firewallCtrl.lock);
    auto entry =
            gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).arg(typeToString(firewallType));
    auto type = static_cast<FirewallType>(firewallType);

    int res = gCtls->firewallCtrl.setFirewallType(type);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::firewallSetInterfaceRule(const std::string& ifName,
                                                           int32_t firewallRule) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->firewallCtrl.lock);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .args(ifName, ruleToString(firewallRule));
    auto rule = static_cast<FirewallRule>(firewallRule);

    int res = gCtls->firewallCtrl.setInterfaceRule(ifName.c_str(), rule);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::firewallSetUidRule(int32_t childChain, int32_t uid,
                                                     int32_t firewallRule) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->firewallCtrl.lock);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .args(chainToString(childChain), uid, ruleToString(firewallRule));
    auto chain = static_cast<ChildChain>(childChain);
    auto rule = static_cast<FirewallRule>(firewallRule);

    int res = gCtls->firewallCtrl.setUidRule(chain, uid, rule);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::firewallEnableChildChain(int32_t childChain, bool enable) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->firewallCtrl.lock);
    auto entry = gLog.newEntry()
                         .prettyFunction(__PRETTY_FUNCTION__)
                         .args(chainToString(childChain), enable);
    auto chain = static_cast<ChildChain>(childChain);

    int res = gCtls->firewallCtrl.enableChildChains(chain, enable);
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::tetherAddForward(const std::string& intIface,
                                                   const std::string& extIface) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).args(intIface, extIface);

    int res = gCtls->tetherCtrl.enableNat(intIface.c_str(), extIface.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::tetherRemoveForward(const std::string& intIface,
                                                      const std::string& extIface) {
    NETD_LOCKING_RPC(NETWORK_STACK, gCtls->tetherCtrl.lock);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).args(intIface, extIface);

    int res = gCtls->tetherCtrl.disableNat(intIface.c_str(), extIface.c_str());
    gLog.log(entry.returns(res).withAutomaticDuration());
    return statusFromErrcode(res);
}

binder::Status NetdNativeService::setTcpRWmemorySize(const std::string& rmemValues,
                                                     const std::string& wmemValues) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__).args(rmemValues, wmemValues);
    if (!WriteStringToFile(rmemValues, TCP_RMEM_PROC_FILE)) {
        int ret = -errno;
        gLog.log(entry.returns(ret).withAutomaticDuration());
        return statusFromErrcode(ret);
    }

    if (!WriteStringToFile(wmemValues, TCP_WMEM_PROC_FILE)) {
        int ret = -errno;
        gLog.log(entry.returns(ret).withAutomaticDuration());
        return statusFromErrcode(ret);
    }
    gLog.log(entry.withAutomaticDuration());
    return binder::Status::ok();
}

binder::Status NetdNativeService::getPrefix64(int netId, std::string* _aidl_return) {
    ENFORCE_PERMISSION(NETWORK_STACK);

    netdutils::IPPrefix prefix{};
    int err = gCtls->resolverCtrl.getPrefix64(netId, &prefix);
    if (err != 0) {
        return binder::Status::fromServiceSpecificError(
                -err, String8::format("ResolverController error: %s", strerror(-err)));
    }
    *_aidl_return = prefix.toString();
    return binder::Status::ok();
}

binder::Status NetdNativeService::registerUnsolicitedEventListener(
        const android::sp<android::net::INetdUnsolicitedEventListener>& listener) {
    ENFORCE_PERMISSION(NETWORK_STACK);
    auto entry = gLog.newEntry().prettyFunction(__PRETTY_FUNCTION__);
    gCtls->eventReporter.registerUnsolEventListener(listener);
    gLog.log(entry.withAutomaticDuration());
    return binder::Status::ok();
}

}  // namespace net
}  // namespace android
