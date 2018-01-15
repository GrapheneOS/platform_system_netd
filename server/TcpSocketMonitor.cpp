/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "TcpSocketMonitor"

#include "TcpSocketMonitor.h"
#include "DumpWriter.h"

#include "SockDiag.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/tcp.h>

namespace android {
namespace net {

constexpr const char* getTcpStateName(int t) {
    switch (t) {
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_SYN_SENT:
            return "SYN-SENT";
        case TCP_SYN_RECV:
            return "SYN-RECV";
        case TCP_FIN_WAIT1:
            return "FIN-WAIT-1";
        case TCP_FIN_WAIT2:
            return "FIN-WAIT-2";
        case TCP_TIME_WAIT:
            return "TIME-WAIT";
        case TCP_CLOSE:
            return "CLOSE";
        case TCP_CLOSE_WAIT:
            return "CLOSE-WAIT";
        case TCP_LAST_ACK:
            return "LAST-ACK";
        case TCP_LISTEN:
            return "LISTEN";
        case TCP_CLOSING:
            return "CLOSING";
        default:
            return "UNKNOWN";
    }
}

static void tcpInfoPrint(DumpWriter &dw, const struct inet_diag_msg *sockinfo,
                         const struct tcp_info *tcpinfo) {
  char saddr[INET6_ADDRSTRLEN] = {};
  char daddr[INET6_ADDRSTRLEN] = {};
  inet_ntop(sockinfo->idiag_family, &(sockinfo->id.idiag_src), saddr, sizeof(saddr));
  inet_ntop(sockinfo->idiag_family, &(sockinfo->id.idiag_dst), daddr, sizeof(daddr));

  dw.println(
      "uid=%u saddr=%s daddr=%s sport=%u dport=%u tcp_state=%s(%u) "
      "rqueue=%u wqueue=%u  rtt=%gms var_rtt=%gms rcv_rtt=%gms unacked=%u snd_cwnd=%u",
      sockinfo->idiag_uid,
      saddr,
      daddr,
      ntohs(sockinfo->id.idiag_sport),
      ntohs(sockinfo->id.idiag_dport),
      getTcpStateName(sockinfo->idiag_state), sockinfo->idiag_state,
      sockinfo->idiag_rqueue,
      sockinfo->idiag_wqueue,
      tcpinfo != nullptr ? tcpinfo->tcpi_rtt/1000.0 : 0,
      tcpinfo != nullptr ? tcpinfo->tcpi_rttvar/1000.0 : 0,
      tcpinfo != nullptr ? tcpinfo->tcpi_rcv_rtt/1000.0 : 0,
      tcpinfo != nullptr ? tcpinfo->tcpi_unacked : 0,
      tcpinfo != nullptr ? tcpinfo->tcpi_snd_cwnd : 0);
}

const String16 TcpSocketMonitor::DUMP_KEYWORD = String16("tcp_socket_info");

void TcpSocketMonitor::dump(DumpWriter& dw) {
    dw.println("TcpSocketMonitor");
    dw.incIndent();

    SockDiag sd;
    if (!sd.open()) {
       ALOGE("Error opening sock diag for dumping TCP socket info");
       return;
    }

    const auto tcpInfoReader = [&dw](const struct inet_diag_msg *sockinfo,
                                     const struct tcp_info *tcpinfo) {
        tcpInfoPrint(dw, sockinfo, tcpinfo);
    };

    if (int ret = sd.getLiveTcpInfos(tcpInfoReader)) {
        ALOGE("Failed to dump TCP socket info: %s", strerror(-ret));
        return;
    }

    dw.decIndent();
}

}  // namespace net
}  // namespace android
