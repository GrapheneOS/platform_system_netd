/*
 * Copyright (C) 2008 The Android Open Source Project
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
 */

// #define LOG_NDEBUG 0

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <linux/if.h>

#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#define LOG_TAG "CommandListener"

#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <log/log.h>
#include <netd_resolv/params.h>
#include <netdutils/ResponseCode.h>
#include <netdutils/Status.h>
#include <netdutils/StatusOr.h>
#include <netutils/ifc.h>
#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "Controllers.h"
#include "NetdConstants.h"

#include "UidRanges.h"
#include "netid_client.h"

#include <string>
#include <vector>

using android::base::Join;
using android::base::StringPrintf;
using android::binder::Status;

#define PARSE_INT_RETURN_IF_FAIL(cli, label, intLabel, errMsg, addErrno)   \
    do {                                                                   \
        if (!android::base::ParseInt(label, &intLabel)) {                  \
            errno = EINVAL;                                                \
            cli->sendMsg(ResponseCode::OperationFailed, errMsg, addErrno); \
            return 0;                                                      \
        }                                                                  \
    } while (0)

#define PARSE_UINT_RETURN_IF_FAIL(cli, label, intLabel, errMsg, addErrno)  \
    do {                                                                   \
        if (!android::base::ParseUint(label, &intLabel)) {                 \
            errno = EINVAL;                                                \
            cli->sendMsg(ResponseCode::OperationFailed, errMsg, addErrno); \
            return 0;                                                      \
        }                                                                  \
    } while (0)

namespace android {

using netdutils::ResponseCode;

namespace net {
namespace {

const unsigned NUM_OEM_IDS = NetworkController::MAX_OEM_ID - NetworkController::MIN_OEM_ID + 1;

unsigned stringToNetId(const char* arg) {
    if (!strcmp(arg, "local")) {
        return NetworkController::LOCAL_NET_ID;
    }
    // OEM NetIds are "oem1", "oem2", .., "oem50".
    if (!strncmp(arg, "oem", 3)) {
        unsigned n = strtoul(arg + 3, nullptr, 0);
        if (1 <= n && n <= NUM_OEM_IDS) {
            return NetworkController::MIN_OEM_ID + n;
        }
        return NETID_UNSET;
    } else if (!strncmp(arg, "handle", 6)) {
        unsigned n = netHandleToNetId((net_handle_t)strtoull(arg + 6, nullptr, 10));
        if (NetworkController::MIN_OEM_ID <= n && n <= NetworkController::MAX_OEM_ID) {
            return n;
        }
        return NETID_UNSET;
    }
    // strtoul() returns 0 on errors, which is fine because 0 is an invalid netId.
    return strtoul(arg, nullptr, 0);
}

std::string toStdString(const String16& s) {
    return std::string(String8(s.string()));
}

int stringToINetdPermission(const char* arg) {
    if (!strcmp(arg, "NETWORK")) {
        return INetd::PERMISSION_NETWORK;
    }
    if (!strcmp(arg, "SYSTEM")) {
        return INetd::PERMISSION_SYSTEM;
    }
    return INetd::PERMISSION_NONE;
}

}  // namespace

sp<INetd> CommandListener::mNetd;

CommandListener::CommandListener() : FrameworkListener(SOCKET_NAME, true) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("netd"));
    if (binder != nullptr) {
        CommandListener::mNetd = interface_cast<INetd>(binder);
    } else {
        ALOGE("Unable to get INetd service");
        exit(1);
    }
    registerCmd(new InterfaceCmd());
    registerCmd(new IpFwdCmd());
    registerCmd(new TetherCmd());
    registerCmd(new NatCmd());
    registerCmd(new BandwidthControlCmd());
    registerCmd(new IdletimerControlCmd());
    registerCmd(new FirewallCmd());
    registerCmd(new ClatdCmd());
    registerCmd(new NetworkCommand());
    registerCmd(new StrictCmd());
}

CommandListener::InterfaceCmd::InterfaceCmd() :
                 NetdCommand("interface") {
}

int CommandListener::InterfaceCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "list")) {
        std::vector<std::string> interfaceGetList;
        Status status = mNetd->interfaceGetList(&interfaceGetList);

        if (!status.isOk()) {
            errno = status.serviceSpecificErrorCode();
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to get interface list", true);
            return 0;
        }
        for (const auto& iface : interfaceGetList) {
            cli->sendMsg(ResponseCode::InterfaceListResult, iface.c_str(), false);
        }

        cli->sendMsg(ResponseCode::CommandOkay, "Interface list completed", false);
        return 0;
    } else {
        /*
         * These commands take a minimum of 3 arguments
         */
        if (argc < 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
            return 0;
        }

        if (!strcmp(argv[1], "getcfg")) {
            InterfaceConfigurationParcel interfaceCfgResult;
            Status status = mNetd->interfaceGetCfg(std::string(argv[2]), &interfaceCfgResult);

            if (!status.isOk()) {
                errno = status.serviceSpecificErrorCode();
                cli->sendMsg(ResponseCode::OperationFailed, "Interface not found", true);
                return 0;
            }

            std::string flags = Join(interfaceCfgResult.flags, " ");

            std::string msg = StringPrintf("%s %s %d %s", interfaceCfgResult.hwAddr.c_str(),
                                           interfaceCfgResult.ipv4Addr.c_str(),
                                           interfaceCfgResult.prefixLength, flags.c_str());

            cli->sendMsg(ResponseCode::InterfaceGetCfgResult, msg.c_str(), false);

            return 0;
        } else if (!strcmp(argv[1], "setcfg")) {
            // arglist: iface [addr prefixLength] flags
            if (argc < 4) {
                cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
                return 0;
            }
            ALOGD("Setting iface cfg");

            struct in_addr addr;
            int index = 5;
            InterfaceConfigurationParcel interfaceCfg;
            interfaceCfg.ifName = argv[2];
            interfaceCfg.hwAddr = "";

            if (!inet_aton(argv[3], &addr)) {
                // Handle flags only case
                index = 3;
                interfaceCfg.ipv4Addr = "";
                interfaceCfg.prefixLength = 0;
            } else {
                if (addr.s_addr != 0) {
                    interfaceCfg.ipv4Addr = argv[3];
                    PARSE_INT_RETURN_IF_FAIL(cli, argv[4], interfaceCfg.prefixLength,
                                             "Failed to set address", true);
                    Status status = mNetd->interfaceSetCfg(interfaceCfg);
                    if (!status.isOk()) {
                        errno = status.serviceSpecificErrorCode();
                        cli->sendMsg(ResponseCode::OperationFailed, "Failed to set address", true);
                        return 0;
                    }
                }
            }

            /* Process flags */
            for (int i = index; i < argc; i++) {
                char *flag = argv[i];
                if (!strcmp(flag, "up")) {
                    ALOGD("Trying to bring up %s", argv[2]);
                    interfaceCfg.flags.push_back(toStdString(INetd::IF_STATE_UP()));
                    Status status = mNetd->interfaceSetCfg(interfaceCfg);
                    if (!status.isOk()) {
                        ALOGE("Error upping interface");
                        errno = status.serviceSpecificErrorCode();
                        cli->sendMsg(ResponseCode::OperationFailed, "Failed to up interface", true);
                        ifc_close();
                        return 0;
                    }
                } else if (!strcmp(flag, "down")) {
                    ALOGD("Trying to bring down %s", argv[2]);
                    interfaceCfg.flags.push_back(toStdString(INetd::IF_STATE_DOWN()));
                    Status status = mNetd->interfaceSetCfg(interfaceCfg);
                    if (!status.isOk()) {
                        ALOGE("Error downing interface");
                        errno = status.serviceSpecificErrorCode();
                        cli->sendMsg(ResponseCode::OperationFailed, "Failed to down interface", true);
                        return 0;
                    }
                } else if (!strcmp(flag, "broadcast")) {
                    // currently ignored
                } else if (!strcmp(flag, "multicast")) {
                    // currently ignored
                } else if (!strcmp(flag, "running")) {
                    // currently ignored
                } else if (!strcmp(flag, "loopback")) {
                    // currently ignored
                } else if (!strcmp(flag, "point-to-point")) {
                    // currently ignored
                } else {
                    cli->sendMsg(ResponseCode::CommandParameterError, "Flag unsupported", false);
                    return 0;
                }
            }

            cli->sendMsg(ResponseCode::CommandOkay, "Interface configuration set", false);
            return 0;
        } else if (!strcmp(argv[1], "clearaddrs")) {
            // arglist: iface
            ALOGD("Clearing all IP addresses on %s", argv[2]);

            mNetd->interfaceClearAddrs(std::string(argv[2]));

            cli->sendMsg(ResponseCode::CommandOkay, "Interface IP addresses cleared", false);
            return 0;
        } else if (!strcmp(argv[1], "ipv6privacyextensions")) {
            if (argc != 4) {
                cli->sendMsg(ResponseCode::CommandSyntaxError,
                        "Usage: interface ipv6privacyextensions <interface> <enable|disable>",
                        false);
                return 0;
            }
            int enable = !strncmp(argv[3], "enable", 7);
            Status status = mNetd->interfaceSetIPv6PrivacyExtensions(std::string(argv[2]), enable);
            if (status.isOk()) {
                cli->sendMsg(ResponseCode::CommandOkay, "IPv6 privacy extensions changed", false);
            } else {
                errno = status.serviceSpecificErrorCode();
                cli->sendMsg(ResponseCode::OperationFailed,
                        "Failed to set ipv6 privacy extensions", true);
            }
            return 0;
        } else if (!strcmp(argv[1], "ipv6")) {
            if (argc != 4) {
                cli->sendMsg(ResponseCode::CommandSyntaxError,
                        "Usage: interface ipv6 <interface> <enable|disable>",
                        false);
                return 0;
            }

            int enable = !strncmp(argv[3], "enable", 7);
            Status status = mNetd->interfaceSetEnableIPv6(std::string(argv[2]), enable);
            if (status.isOk()) {
                cli->sendMsg(ResponseCode::CommandOkay, "IPv6 state changed", false);
            } else {
                errno = status.serviceSpecificErrorCode();
                cli->sendMsg(ResponseCode::OperationFailed,
                        "Failed to change IPv6 state", true);
            }
            return 0;
        } else if (!strcmp(argv[1], "setmtu")) {
            if (argc != 4) {
                cli->sendMsg(ResponseCode::CommandSyntaxError,
                        "Usage: interface setmtu <interface> <val>", false);
                return 0;
            }

            int mtuValue = 0;
            PARSE_INT_RETURN_IF_FAIL(cli, argv[3], mtuValue, "Failed to set MTU", true);
            Status status = mNetd->interfaceSetMtu(std::string(argv[2]), mtuValue);
            if (status.isOk()) {
                cli->sendMsg(ResponseCode::CommandOkay, "MTU changed", false);
            } else {
                errno = status.serviceSpecificErrorCode();
                cli->sendMsg(ResponseCode::OperationFailed,
                        "Failed to set MTU", true);
            }
            return 0;
        } else {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown interface cmd", false);
            return 0;
        }
    }
    return 0;
}

CommandListener::IpFwdCmd::IpFwdCmd() :
                 NetdCommand("ipfwd") {
}

int CommandListener::IpFwdCmd::runCommand(SocketClient *cli, int argc, char **argv) {
    bool matched = false;
    Status status;

    if (argc == 2) {
        //   0     1
        // ipfwd status
        if (!strcmp(argv[1], "status")) {
            bool ipfwdEnabled;
            mNetd->ipfwdEnabled(&ipfwdEnabled);
            std::string msg = StringPrintf("Forwarding %s", ipfwdEnabled ? "enabled" : "disabled");
            cli->sendMsg(ResponseCode::IpFwdStatusResult, msg.c_str(), false);
            return 0;
        }
    } else if (argc == 3) {
        //  0      1         2
        // ipfwd enable  <requester>
        // ipfwd disable <requester>
        if (!strcmp(argv[1], "enable")) {
            matched = true;
            status = mNetd->ipfwdEnableForwarding(argv[2]);
        } else if (!strcmp(argv[1], "disable")) {
            matched = true;
            status = mNetd->ipfwdDisableForwarding(argv[2]);
        }
    } else if (argc == 4) {
        //  0      1      2     3
        // ipfwd  add   wlan0 dummy0
        // ipfwd remove wlan0 dummy0
        if (!strcmp(argv[1], "add")) {
            matched = true;
            status = mNetd->ipfwdAddInterfaceForward(argv[2], argv[3]);
        } else if (!strcmp(argv[1], "remove")) {
            matched = true;
            status = mNetd->ipfwdRemoveInterfaceForward(argv[2], argv[3]);
        }
    }

    if (!matched) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown ipfwd cmd", false);
        return 0;
    }

    if (status.isOk()) {
        cli->sendMsg(ResponseCode::CommandOkay, "ipfwd operation succeeded", false);
    } else {
        errno = status.serviceSpecificErrorCode();
        cli->sendMsg(ResponseCode::OperationFailed, "ipfwd operation failed", true);
    }
    return 0;
}

CommandListener::TetherCmd::TetherCmd() :
                 NetdCommand("tether") {
}

int CommandListener::TetherCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    Status status;

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "stop")) {
        status = mNetd->tetherStop();
    } else if (!strcmp(argv[1], "status")) {
        bool tetherEnabled;
        mNetd->tetherIsEnabled(&tetherEnabled);
        std::string msg =
                StringPrintf("Tethering services %s", tetherEnabled ? "started" : "stopped");
        cli->sendMsg(ResponseCode::TetherStatusResult, msg.c_str(), false);
        return 0;
    } else if (argc == 3) {
        if (!strcmp(argv[1], "interface") && !strcmp(argv[2], "list")) {
            std::vector<std::string> ifList;
            mNetd->tetherInterfaceList(&ifList);
            for (const auto& ifname : ifList) {
                cli->sendMsg(ResponseCode::TetherInterfaceListResult, ifname.c_str(), false);
            }
        } else if (!strcmp(argv[1], "dns") && !strcmp(argv[2], "list")) {
            // It is not supported in binder currently since NMS doesn't need DnsNetId.
            // TODO: Fix it after migrate to ndc.
            char netIdStr[UINT32_STRLEN];
            snprintf(netIdStr, sizeof(netIdStr), "%u", gCtls->tetherCtrl.getDnsNetId());
            cli->sendMsg(ResponseCode::TetherDnsFwdNetIdResult, netIdStr, false);

            std::vector<std::string> dnsList;
            mNetd->tetherDnsList(&dnsList);
            for (const auto& fwdr : dnsList) {
                cli->sendMsg(ResponseCode::TetherDnsFwdTgtListResult, fwdr.c_str(), false);
            }
        }
    } else if (!strcmp(argv[1], "start")) {
        if (argc % 2 == 1) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Bad number of arguments", false);
            return 0;
        }

        std::vector<std::string> dhcpRanges;
        // We do the checking of the pairs & addr invalidation in binderService/tetherController.
        for (int arg_index = 2; arg_index < argc; arg_index++) {
            dhcpRanges.push_back(argv[arg_index]);
        }

        status = mNetd->tetherStart(dhcpRanges);
    } else {
        /*
         * These commands take a minimum of 4 arguments
         */
        if (argc < 4) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
            return 0;
        }

        if (!strcmp(argv[1], "interface")) {
            if (!strcmp(argv[2], "add")) {
                status = mNetd->tetherInterfaceAdd(argv[3]);
            } else if (!strcmp(argv[2], "remove")) {
                status = mNetd->tetherInterfaceRemove(argv[3]);
                /* else if (!strcmp(argv[2], "list")) handled above */
            } else {
                cli->sendMsg(ResponseCode::CommandParameterError,
                             "Unknown tether interface operation", false);
                return 0;
            }
        } else if (!strcmp(argv[1], "dns")) {
            if (!strcmp(argv[2], "set")) {
                if (argc < 5) {
                    cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
                    return 0;
                }
                std::vector<std::string> tetherDnsAddrs;
                unsigned netId = stringToNetId(argv[3]);
                for (int arg_index = 4; arg_index < argc; arg_index++) {
                    tetherDnsAddrs.push_back(argv[arg_index]);
                }
                status = mNetd->tetherDnsSet(netId, tetherDnsAddrs);
                /* else if (!strcmp(argv[2], "list")) handled above */
            } else {
                cli->sendMsg(ResponseCode::CommandParameterError,
                             "Unknown tether interface operation", false);
                return 0;
            }
        } else {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown tether cmd", false);
            return 0;
        }
    }

    if (status.isOk()) {
        cli->sendMsg(ResponseCode::CommandOkay, "Tether operation succeeded", false);
    } else {
        errno = status.serviceSpecificErrorCode();
        cli->sendMsg(ResponseCode::OperationFailed, "Tether operation failed", true);
    }

    return 0;
}

CommandListener::NatCmd::NatCmd() :
                 NetdCommand("nat") {
}

int CommandListener::NatCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    Status status;

    if (argc < 5) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    //  0     1       2        3
    // nat  enable intiface extiface
    // nat disable intiface extiface
    if (!strcmp(argv[1], "enable") && argc >= 4) {
        status = mNetd->tetherAddForward(argv[2], argv[3]);
    } else if (!strcmp(argv[1], "disable") && argc >= 4) {
        status = mNetd->tetherRemoveForward(argv[2], argv[3]);
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown nat cmd", false);
        return 0;
    }

    if (status.isOk()) {
        cli->sendMsg(ResponseCode::CommandOkay, "Nat operation succeeded", false);
    } else {
        errno = status.serviceSpecificErrorCode();
        cli->sendMsg(ResponseCode::OperationFailed, "Nat operation failed", true);
    }

    return 0;
}

CommandListener::BandwidthControlCmd::BandwidthControlCmd() :
    NetdCommand("bandwidth") {
}

void CommandListener::BandwidthControlCmd::sendGenericSyntaxError(SocketClient *cli, const char *usageMsg) {
    char *msg;
    asprintf(&msg, "Usage: bandwidth %s", usageMsg);
    cli->sendMsg(ResponseCode::CommandSyntaxError, msg, false);
    free(msg);
}

void CommandListener::BandwidthControlCmd::sendGenericOkFail(SocketClient *cli, int cond) {
    if (!cond) {
        cli->sendMsg(ResponseCode::CommandOkay, "Bandwidth command succeeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Bandwidth command failed", false);
    }
}

void CommandListener::BandwidthControlCmd::sendGenericOpFailed(SocketClient *cli, const char *errMsg) {
    cli->sendMsg(ResponseCode::OperationFailed, errMsg, false);
}

int CommandListener::BandwidthControlCmd::runCommand(SocketClient *cli, int argc, char **argv) {
    if (argc < 2) {
        sendGenericSyntaxError(cli, "<cmds> <args...>");
        return 0;
    }

    ALOGV("bwctrlcmd: argc=%d %s %s ...", argc, argv[0], argv[1]);

    if (!strcmp(argv[1], "removeiquota") || !strcmp(argv[1], "riq")) {
        if (argc != 3) {
            sendGenericSyntaxError(cli, "removeiquota <interface>");
            return 0;
        }
        int rc = !mNetd->bandwidthRemoveInterfaceQuota(argv[2]).isOk();
        sendGenericOkFail(cli, rc);
        return 0;

    }
    if (!strcmp(argv[1], "setiquota") || !strcmp(argv[1], "siq")) {
        if (argc != 4) {
            sendGenericSyntaxError(cli, "setiquota <interface> <bytes>");
            return 0;
        }
        int64_t bytes = 0;
        PARSE_INT_RETURN_IF_FAIL(cli, argv[3], bytes, "Bandwidth command failed", false);
        int rc = !mNetd->bandwidthSetInterfaceQuota(argv[2], bytes).isOk();
        sendGenericOkFail(cli, rc);
        return 0;

    }
    if (!strcmp(argv[1], "addnaughtyapps") || !strcmp(argv[1], "ana")) {
        if (argc < 3) {
            sendGenericSyntaxError(cli, "addnaughtyapps <appUid> ...");
            return 0;
        }
        int rc = 0;
        for (int arg_index = 2; arg_index < argc; arg_index++) {
            uid_t uid = 0;
            PARSE_UINT_RETURN_IF_FAIL(cli, argv[arg_index], uid, "Bandwidth command failed", false);
            rc = !mNetd->bandwidthAddNaughtyApp(uid).isOk();
            if (rc) break;
        }
        sendGenericOkFail(cli, rc);
        return 0;
    }
    if (!strcmp(argv[1], "removenaughtyapps") || !strcmp(argv[1], "rna")) {
        if (argc < 3) {
            sendGenericSyntaxError(cli, "removenaughtyapps <appUid> ...");
            return 0;
        }
        int rc = 0;
        for (int arg_index = 2; arg_index < argc; arg_index++) {
            uid_t uid = 0;
            PARSE_UINT_RETURN_IF_FAIL(cli, argv[arg_index], uid, "Bandwidth command failed", false);
            rc = !mNetd->bandwidthRemoveNaughtyApp(uid).isOk();
            if (rc) break;
        }
        sendGenericOkFail(cli, rc);
        return 0;
    }
    if (!strcmp(argv[1], "addniceapps") || !strcmp(argv[1], "aha")) {
        if (argc < 3) {
            sendGenericSyntaxError(cli, "addniceapps <appUid> ...");
            return 0;
        }
        int rc = 0;
        for (int arg_index = 2; arg_index < argc; arg_index++) {
            uid_t uid = 0;
            PARSE_UINT_RETURN_IF_FAIL(cli, argv[arg_index], uid, "Bandwidth command failed", false);
            rc = !mNetd->bandwidthAddNiceApp(uid).isOk();
            if (rc) break;
        }
        sendGenericOkFail(cli, rc);
        return 0;
    }
    if (!strcmp(argv[1], "removeniceapps") || !strcmp(argv[1], "rha")) {
        if (argc < 3) {
            sendGenericSyntaxError(cli, "removeniceapps <appUid> ...");
            return 0;
        }
        int rc = 0;
        for (int arg_index = 2; arg_index < argc; arg_index++) {
            uid_t uid = 0;
            PARSE_UINT_RETURN_IF_FAIL(cli, argv[arg_index], uid, "Bandwidth command failed", false);
            rc = !mNetd->bandwidthRemoveNiceApp(uid).isOk();
            if (rc) break;
        }
        sendGenericOkFail(cli, rc);
        return 0;
    }
    if (!strcmp(argv[1], "setglobalalert") || !strcmp(argv[1], "sga")) {
        if (argc != 3) {
            sendGenericSyntaxError(cli, "setglobalalert <bytes>");
            return 0;
        }
        int64_t bytes = 0;
        PARSE_INT_RETURN_IF_FAIL(cli, argv[2], bytes, "Bandwidth command failed", false);
        int rc = !mNetd->bandwidthSetGlobalAlert(bytes).isOk();
        sendGenericOkFail(cli, rc);
        return 0;
    }
    if (!strcmp(argv[1], "setinterfacealert") || !strcmp(argv[1], "sia")) {
        if (argc != 4) {
            sendGenericSyntaxError(cli, "setinterfacealert <interface> <bytes>");
            return 0;
        }
        int64_t bytes = 0;
        PARSE_INT_RETURN_IF_FAIL(cli, argv[3], bytes, "Bandwidth command failed", false);
        int rc = !mNetd->bandwidthSetInterfaceAlert(argv[2], bytes).isOk();
        sendGenericOkFail(cli, rc);
        return 0;

    }
    if (!strcmp(argv[1], "removeinterfacealert") || !strcmp(argv[1], "ria")) {
        if (argc != 3) {
            sendGenericSyntaxError(cli, "removeinterfacealert <interface>");
            return 0;
        }
        int rc = !mNetd->bandwidthRemoveInterfaceAlert(argv[2]).isOk();
        sendGenericOkFail(cli, rc);
        return 0;

    }

    cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown bandwidth cmd", false);
    return 0;
}

CommandListener::IdletimerControlCmd::IdletimerControlCmd() :
    NetdCommand("idletimer") {
}

int CommandListener::IdletimerControlCmd::runCommand(SocketClient *cli, int argc, char **argv) {
  // TODO(ashish): Change the error statements
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    ALOGV("idletimerctrlcmd: argc=%d %s %s ...", argc, argv[0], argv[1]);

    if (!strcmp(argv[1], "add")) {
        if (argc != 5) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
            return 0;
        }

        int timeout = 0;
        PARSE_INT_RETURN_IF_FAIL(cli, argv[3], timeout, "Failed to add interface", false);
        Status status = mNetd->idletimerAddInterface(argv[2], timeout, argv[4]);
        if (!status.isOk()) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to add interface", false);
        } else {
          cli->sendMsg(ResponseCode::CommandOkay,  "Add success", false);
        }
        return 0;
    }
    if (!strcmp(argv[1], "remove")) {
        if (argc != 5) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
            return 0;
        }
        int timeout = 0;
        PARSE_INT_RETURN_IF_FAIL(cli, argv[3], timeout, "Failed to remove interface", false);
        Status status = mNetd->idletimerRemoveInterface(argv[2], timeout, argv[4]);
        if (!status.isOk()) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to remove interface", false);
        } else {
          cli->sendMsg(ResponseCode::CommandOkay, "Remove success", false);
        }
        return 0;
    }

    cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown idletimer cmd", false);
    return 0;
}

CommandListener::FirewallCmd::FirewallCmd() :
    NetdCommand("firewall") {
}

int CommandListener::FirewallCmd::sendGenericOkFail(SocketClient *cli, int cond) {
    if (!cond) {
        cli->sendMsg(ResponseCode::CommandOkay, "Firewall command succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Firewall command failed", false);
    }
    return 0;
}

int CommandListener::FirewallCmd::parseRule(const char* arg) {
    if (!strcmp(arg, "allow")) {
        return INetd::FIREWALL_RULE_ALLOW;
    } else if (!strcmp(arg, "deny")) {
        return INetd::FIREWALL_RULE_DENY;
    } else {
        ALOGE("failed to parse uid rule (%s)", arg);
        return INetd::FIREWALL_RULE_ALLOW;
    }
}

int CommandListener::FirewallCmd::parseFirewallType(const char* arg) {
    if (!strcmp(arg, "whitelist")) {
        return INetd::FIREWALL_WHITELIST;
    } else if (!strcmp(arg, "blacklist")) {
        return INetd::FIREWALL_BLACKLIST;
    } else {
        ALOGE("failed to parse firewall type (%s)", arg);
        return INetd::FIREWALL_BLACKLIST;
    }
}

int CommandListener::FirewallCmd::parseChildChain(const char* arg) {
    if (!strcmp(arg, "dozable")) {
        return INetd::FIREWALL_CHAIN_DOZABLE;
    } else if (!strcmp(arg, "standby")) {
        return INetd::FIREWALL_CHAIN_STANDBY;
    } else if (!strcmp(arg, "powersave")) {
        return INetd::FIREWALL_CHAIN_POWERSAVE;
    } else if (!strcmp(arg, "none")) {
        return INetd::FIREWALL_CHAIN_NONE;
    } else {
        ALOGE("failed to parse child firewall chain (%s)", arg);
        return -1;
    }
}

int CommandListener::FirewallCmd::runCommand(SocketClient *cli, int argc,
        char **argv) {
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing command", false);
        return 0;
    }

    if (!strcmp(argv[1], "enable")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                        "Usage: firewall enable <whitelist|blacklist>", false);
            return 0;
        }
        int res = !mNetd->firewallSetFirewallType(parseFirewallType(argv[2])).isOk();
        return sendGenericOkFail(cli, res);
    }

    if (!strcmp(argv[1], "set_interface_rule")) {
        if (argc != 4) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: firewall set_interface_rule <rmnet0> <allow|deny>", false);
            return 0;
        }
        int res = !mNetd->firewallSetInterfaceRule(argv[2], parseRule(argv[3])).isOk();
        return sendGenericOkFail(cli, res);
    }

    if (!strcmp(argv[1], "set_uid_rule")) {
        if (argc != 5) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: firewall set_uid_rule <dozable|standby|none> <1000> <allow|deny>",
                         false);
            return 0;
        }

        int childChain = parseChildChain(argv[2]);
        if (childChain == -1) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Invalid chain name. Valid names are: <dozable|standby|none>",
                         false);
            return 0;
        }
        uid_t uid = 0;
        PARSE_UINT_RETURN_IF_FAIL(cli, argv[3], uid, "Firewall command failed", false);
        int res = !mNetd->firewallSetUidRule(childChain, uid, parseRule(argv[4])).isOk();
        return sendGenericOkFail(cli, res);
    }

    if (!strcmp(argv[1], "enable_chain")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: firewall enable_chain <dozable|standby>",
                         false);
            return 0;
        }
        int res = !mNetd->firewallEnableChildChain(parseChildChain(argv[2]), true).isOk();
        return sendGenericOkFail(cli, res);
    }

    if (!strcmp(argv[1], "disable_chain")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: firewall disable_chain <dozable|standby>",
                         false);
            return 0;
        }
        int res = !mNetd->firewallEnableChildChain(parseChildChain(argv[2]), false).isOk();
        return sendGenericOkFail(cli, res);
    }

    cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown command", false);
    return 0;
}

CommandListener::ClatdCmd::ClatdCmd() : NetdCommand("clatd") {
}

int CommandListener::ClatdCmd::runCommand(SocketClient* cli, int argc, char** argv) {
    int rc = 0;
    if (argc < 3) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
        return 0;
    }

    std::string v6Addr;

    if (!strcmp(argv[1], "stop")) {
        rc = !mNetd->clatdStop(argv[2]).isOk();
    } else if (!strcmp(argv[1], "start")) {
        if (argc < 4) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing argument", false);
            return 0;
        }
        rc = !mNetd->clatdStart(argv[2], argv[3], &v6Addr).isOk();
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown clatd cmd", false);
        return 0;
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay,
                     std::string(("Clatd operation succeeded ") + v6Addr).c_str(), false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Clatd operation failed", false);
    }

    return 0;
}

CommandListener::StrictCmd::StrictCmd() :
    NetdCommand("strict") {
}

int CommandListener::StrictCmd::sendGenericOkFail(SocketClient *cli, int cond) {
    if (!cond) {
        cli->sendMsg(ResponseCode::CommandOkay, "Strict command succeeded", false);
    } else {
        cli->sendMsg(ResponseCode::OperationFailed, "Strict command failed", false);
    }
    return 0;
}

int CommandListener::StrictCmd::parsePenalty(const char* arg) {
    if (!strcmp(arg, "reject")) {
        return INetd::PENALTY_POLICY_REJECT;
    } else if (!strcmp(arg, "log")) {
        return INetd::PENALTY_POLICY_LOG;
    } else if (!strcmp(arg, "accept")) {
        return INetd::PENALTY_POLICY_ACCEPT;
    } else {
        return -1;
    }
}

int CommandListener::StrictCmd::runCommand(SocketClient *cli, int argc,
        char **argv) {
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing command", false);
        return 0;
    }

    if (!strcmp(argv[1], "set_uid_cleartext_policy")) {
        if (argc != 4) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                         "Usage: strict set_uid_cleartext_policy <uid> <accept|log|reject>",
                         false);
            return 0;
        }

        errno = 0;
        uid_t uid = 0;
        PARSE_UINT_RETURN_IF_FAIL(cli, argv[2], uid, "Invalid UID", false);
        if (uid > UID_MAX) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Invalid UID", false);
            return 0;
        }

        int penalty = parsePenalty(argv[3]);
        if (penalty == -1) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Invalid penalty argument", false);
            return 0;
        }

        int res = !mNetd->strictUidCleartextPenalty(uid, penalty).isOk();
        return sendGenericOkFail(cli, res);
    }

    cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown command", false);
    return 0;
}

CommandListener::NetworkCommand::NetworkCommand() : NetdCommand("network") {
}

int CommandListener::NetworkCommand::syntaxError(SocketClient* client, const char* message) {
    client->sendMsg(ResponseCode::CommandSyntaxError, message, false);
    return 0;
}

int CommandListener::NetworkCommand::operationError(SocketClient* client, const char* message,
                                                    int ret) {
    errno = ret;
    client->sendMsg(ResponseCode::OperationFailed, message, true);
    return 0;
}

int CommandListener::NetworkCommand::success(SocketClient* client) {
    client->sendMsg(ResponseCode::CommandOkay, "success", false);
    return 0;
}

int CommandListener::NetworkCommand::runCommand(SocketClient* client, int argc, char** argv) {
    if (argc < 2) {
        return syntaxError(client, "Missing argument");
    }

    //    0      1      2      3      4       5         6            7           8
    // network route [legacy <uid>]  add   <netId> <interface> <destination> [nexthop]
    // network route [legacy <uid>] remove <netId> <interface> <destination> [nexthop]
    //
    // nexthop may be either an IPv4/IPv6 address or one of "unreachable" or "throw".
    if (!strcmp(argv[1], "route")) {
        if (argc < 6 || argc > 9) {
            return syntaxError(client, "Incorrect number of arguments");
        }

        int nextArg = 2;
        bool legacy = false;
        uid_t uid = 0;
        if (!strcmp(argv[nextArg], "legacy")) {
            ++nextArg;
            legacy = true;
            PARSE_UINT_RETURN_IF_FAIL(client, argv[nextArg++], uid, "Unknown argument", false);
        }

        bool add = false;
        if (!strcmp(argv[nextArg], "add")) {
            add = true;
        } else if (strcmp(argv[nextArg], "remove")) {
            return syntaxError(client, "Unknown argument");
        }
        ++nextArg;

        if (argc < nextArg + 3 || argc > nextArg + 4) {
            return syntaxError(client, "Incorrect number of arguments");
        }

        unsigned netId = stringToNetId(argv[nextArg++]);
        const char* interface = argv[nextArg++];
        const char* destination = argv[nextArg++];
        const char* nexthop = argc > nextArg ? argv[nextArg] : "";

        Status status;
        if (legacy) {
            status = add ? mNetd->networkAddLegacyRoute(netId, interface, destination, nexthop, uid)

                         : mNetd->networkRemoveLegacyRoute(netId, interface, destination, nexthop,
                                                           uid);
        } else {
            status = add ? mNetd->networkAddRoute(netId, interface, destination, nexthop)
                         : mNetd->networkRemoveRoute(netId, interface, destination, nexthop);
        }

        if (!status.isOk()) {
            return operationError(client, add ? "addRoute() failed" : "removeRoute() failed",
                                  status.serviceSpecificErrorCode());
        }

        return success(client);
    }

    //    0        1       2       3         4
    // network interface  add   <netId> <interface>
    // network interface remove <netId> <interface>
    if (!strcmp(argv[1], "interface")) {
        if (argc != 5) {
            return syntaxError(client, "Missing argument");
        }
        unsigned netId = stringToNetId(argv[3]);
        if (!strcmp(argv[2], "add")) {
            if (Status status = mNetd->networkAddInterface(netId, argv[4]); !status.isOk()) {
                return operationError(client, "addInterfaceToNetwork() failed",
                                      status.serviceSpecificErrorCode());
            }
        } else if (!strcmp(argv[2], "remove")) {
            if (Status status = mNetd->networkRemoveInterface(netId, argv[4]); !status.isOk()) {
                return operationError(client, "removeInterfaceFromNetwork() failed",
                                      status.serviceSpecificErrorCode());
            }
        } else {
            return syntaxError(client, "Unknown argument");
        }
        return success(client);
    }

    //    0      1       2         3
    // network create <netId> [permission]
    //
    //    0      1       2     3      4
    // network create <netId> vpn <secure>
    if (!strcmp(argv[1], "create")) {
        if (argc < 3) {
            return syntaxError(client, "Missing argument");
        }
        unsigned netId = stringToNetId(argv[2]);
        if (argc == 6 && !strcmp(argv[3], "vpn")) {
            bool secure = strtol(argv[4], nullptr, 2);
            if (Status status = mNetd->networkCreateVpn(netId, secure); !status.isOk()) {
                return operationError(client, "createVirtualNetwork() failed",
                                      status.serviceSpecificErrorCode());
            }
        } else if (argc > 4) {
            return syntaxError(client, "Unknown trailing argument(s)");
        } else {
            int permission = INetd::PERMISSION_NONE;
            if (argc == 4) {
                permission = stringToINetdPermission(argv[3]);
                if (permission == INetd::PERMISSION_NONE) {
                    return syntaxError(client, "Unknown permission");
                }
            }
            if (Status status = mNetd->networkCreatePhysical(netId, permission); !status.isOk()) {
                return operationError(client, "createPhysicalNetwork() failed",
                                      status.serviceSpecificErrorCode());
            }
        }
        return success(client);
    }

    //    0       1       2
    // network destroy <netId>
    if (!strcmp(argv[1], "destroy")) {
        if (argc != 3) {
            return syntaxError(client, "Incorrect number of arguments");
        }
        unsigned netId = stringToNetId(argv[2]);
        // Both of these functions manage their own locking internally.
        if (Status status = mNetd->networkDestroy(netId); !status.isOk()) {
            return operationError(client, "destroyNetwork() failed",
                                  status.serviceSpecificErrorCode());
        }
        // TODO: add clearing DNS back after NDC migrating to binder ver.
        return success(client);
    }

    //    0       1      2      3
    // network default  set  <netId>
    // network default clear
    if (!strcmp(argv[1], "default")) {
        if (argc < 3) {
            return syntaxError(client, "Missing argument");
        }
        unsigned netId = NETID_UNSET;
        if (!strcmp(argv[2], "set")) {
            if (argc < 4) {
                return syntaxError(client, "Missing netId");
            }
            netId = stringToNetId(argv[3]);
        } else if (strcmp(argv[2], "clear")) {
            return syntaxError(client, "Unknown argument");
        }
        if (Status status = mNetd->networkSetDefault(netId); status.isOk()) {
            return operationError(client, "setDefaultNetwork() failed",
                                  status.serviceSpecificErrorCode());
        }
        return success(client);
    }

    //    0        1         2      3        4          5
    // network permission   user   set  <permission>  <uid> ...
    // network permission   user  clear    <uid> ...
    // network permission network  set  <permission> <netId> ...
    // network permission network clear   <netId> ...
    if (!strcmp(argv[1], "permission")) {
        if (argc < 5) {
            return syntaxError(client, "Missing argument");
        }
        int nextArg = 4;
        int permission = INetd::PERMISSION_NONE;
        if (!strcmp(argv[3], "set")) {
            permission = stringToINetdPermission(argv[4]);
            if (permission == INetd::PERMISSION_NONE) {
                return syntaxError(client, "Unknown permission");
            }
            nextArg = 5;
        } else if (strcmp(argv[3], "clear")) {
            return syntaxError(client, "Unknown argument");
        }
        if (nextArg == argc) {
            return syntaxError(client, "Missing id");
        }

        bool userPermissions = !strcmp(argv[2], "user");
        bool networkPermissions = !strcmp(argv[2], "network");
        if (!userPermissions && !networkPermissions) {
            return syntaxError(client, "Unknown argument");
        }

        std::vector<int32_t> ids;
        for (; nextArg < argc; ++nextArg) {
            if (userPermissions) {
                char* endPtr;
                unsigned id = strtoul(argv[nextArg], &endPtr, 0);
                if (!*argv[nextArg] || *endPtr) {
                    return syntaxError(client, "Invalid id");
                }
                ids.push_back(id);
            } else {
                // networkPermissions
                ids.push_back(stringToNetId(argv[nextArg]));
            }
        }
        if (userPermissions) {
            mNetd->networkSetPermissionForUser(permission, ids);
        } else {
            // networkPermissions
            for (auto netId : ids) {
                Status status = mNetd->networkSetPermissionForNetwork(netId, permission);
                if (!status.isOk())
                    return operationError(client, "setPermissionForNetworks() failed",
                                          status.serviceSpecificErrorCode());
            }
        }

        return success(client);
    }

    //    0      1     2       3           4
    // network users  add   <netId> [<uid>[-<uid>]] ...
    // network users remove <netId> [<uid>[-<uid>]] ...
    if (!strcmp(argv[1], "users")) {
        if (argc < 4) {
            return syntaxError(client, "Missing argument");
        }
        unsigned netId = stringToNetId(argv[3]);
        UidRanges uidRanges;
        if (!uidRanges.parseFrom(argc - 4, argv + 4)) {
            return syntaxError(client, "Invalid UIDs");
        }
        if (!strcmp(argv[2], "add")) {
            if (Status status = mNetd->networkAddUidRanges(netId, uidRanges.getRanges());
                !status.isOk()) {
                return operationError(client, "addUsersToNetwork() failed",
                                      status.serviceSpecificErrorCode());
            }
        } else if (!strcmp(argv[2], "remove")) {
            if (Status status = mNetd->networkRemoveUidRanges(netId, uidRanges.getRanges());
                !status.isOk()) {
                return operationError(client, "removeUsersFromNetwork() failed",
                                      status.serviceSpecificErrorCode());
            }
        } else {
            return syntaxError(client, "Unknown argument");
        }
        return success(client);
    }

    //    0       1      2     3
    // network protect allow <uid> ...
    // network protect  deny <uid> ...
    if (!strcmp(argv[1], "protect")) {
        if (argc < 4) {
            return syntaxError(client, "Missing argument");
        }
        std::vector<uid_t> uids;
        for (int i = 3; i < argc; ++i) {
            uid_t uid = 0;
            PARSE_UINT_RETURN_IF_FAIL(client, argv[i], uid, "Unknown argument", false);
            uids.push_back(uid);
        }
        if (!strcmp(argv[2], "allow")) {
            for (auto uid : uids) {
                mNetd->networkSetProtectAllow(uid);
            }
        } else if (!strcmp(argv[2], "deny")) {
            for (auto uid : uids) {
                mNetd->networkSetProtectDeny(uid);
            }
        } else {
            return syntaxError(client, "Unknown argument");
        }
        return success(client);
    }

    return syntaxError(client, "Unknown argument");
}

}  // namespace net
}  // namespace android
