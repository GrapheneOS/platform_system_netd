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

#include <iomanip>
#include <thread>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/tcp.h>

#include "DumpWriter.h"
#include "Fwmark.h"
#include "SockDiag.h"
#include "TcpSocketMonitor.h"

namespace android {
namespace net {

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

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

static void tcpInfoPrint(DumpWriter &dw, Fwmark mark, const struct inet_diag_msg *sockinfo,
                         const struct tcp_info *tcpinfo) {
    char saddr[INET6_ADDRSTRLEN] = {};
    char daddr[INET6_ADDRSTRLEN] = {};
    inet_ntop(sockinfo->idiag_family, &(sockinfo->id.idiag_src), saddr, sizeof(saddr));
    inet_ntop(sockinfo->idiag_family, &(sockinfo->id.idiag_dst), daddr, sizeof(daddr));

    dw.println(
            "netId=%d uid=%u mark=0x%x saddr=%s daddr=%s sport=%u dport=%u tcp_state=%s(%u) "
            "rqueue=%u wqueue=%u  rtt=%gms var_rtt=%gms rcv_rtt=%gms unacked=%u snd_cwnd=%u",
            mark.netId,
            sockinfo->idiag_uid,
            mark.intValue,
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
const milliseconds TcpSocketMonitor::kDefaultPollingInterval = milliseconds(30000);

void TcpSocketMonitor::dump(DumpWriter& dw) {
    std::lock_guard<std::mutex> guard(mLock);

    dw.println("TcpSocketMonitor");
    dw.incIndent();

    const auto now = steady_clock::now();
    const auto d = duration_cast<milliseconds>(now - mLastPoll);
    dw.println("last poll %lld ms ago", d.count());

    SockDiag sd;
    if (!sd.open()) {
        ALOGE("Error opening sock diag for dumping TCP socket info");
        return;
    }

    const auto tcpInfoReader = [&dw](Fwmark mark, const struct inet_diag_msg *sockinfo,
                                     const struct tcp_info *tcpinfo) {
        tcpInfoPrint(dw, mark, sockinfo, tcpinfo);
    };

    if (int ret = sd.getLiveTcpInfos(tcpInfoReader)) {
        ALOGE("Failed to dump TCP socket info: %s", strerror(-ret));
        return;
    }

    dw.decIndent();
}

void TcpSocketMonitor::setPollingInterval(milliseconds nextSleepDurationMs) {
    std::lock_guard<std::mutex> guard(mLock);

    mNextSleepDurationMs = nextSleepDurationMs;

    ALOGD("tcpinfo polling interval set to %lld ms", mNextSleepDurationMs.count());
}

void TcpSocketMonitor::resumePolling() {
    {
        std::lock_guard<std::mutex> guard(mLock);

        if (!mIsSuspended) {
            return;
        }

        mIsSuspended = false;

        ALOGD("resuming tcpinfo polling with polling interval set to %lld ms",
                mNextSleepDurationMs.count());
    }

    mCv.notify_all();
}

void TcpSocketMonitor::suspendPolling() {
    std::lock_guard<std::mutex> guard(mLock);

    if (!mIsSuspended) {
        ALOGD("suspending tcpinfo polling");
        mIsSuspended = true;
    }
}

void TcpSocketMonitor::poll() {
    std::lock_guard<std::mutex> guard(mLock);

    if (mIsSuspended) {
        return;
    }

    const auto now = steady_clock::now();

    SockDiag sd;
    if (!sd.open()) {
        ALOGE("Error opening sock diag for polling TCP socket info");
        return;
    }

    const auto tcpInfoReader = [](Fwmark mark, const struct inet_diag_msg *sockinfo,
                                const struct tcp_info *tcpinfo) {
        if (sockinfo == nullptr || tcpinfo == nullptr || mark.intValue == 0) {
            return;
        }

        // TODO: process socket stats
    };

    if (int ret = sd.getLiveTcpInfos(tcpInfoReader)) {
        ALOGE("Failed to poll TCP socket info: %s", strerror(-ret));
        return;
    }

    mLastPoll = now;
}

void TcpSocketMonitor::waitForNextPoll() {
    bool isSuspended;
    milliseconds nextSleepDurationMs;
    {
        std::lock_guard<std::mutex> guard(mLock);
        isSuspended = mIsSuspended;
        nextSleepDurationMs= mNextSleepDurationMs;
    }

    std::unique_lock<std::mutex> ul(mLock);
    if (isSuspended) {
        mCv.wait(ul);
    } else {
        mCv.wait_for(ul, nextSleepDurationMs);
    }
}

bool TcpSocketMonitor::isRunning() {
    std::lock_guard<std::mutex> guard(mLock);
    return mIsRunning;
}

TcpSocketMonitor::TcpSocketMonitor() {
    std::lock_guard<std::mutex> guard(mLock);

    mNextSleepDurationMs = kDefaultPollingInterval;
    mIsSuspended = true;
    mIsRunning = true;
    mPollingThread = std::thread([this] {
        while (isRunning()) {
            poll();
            waitForNextPoll();
        }
    });
}

TcpSocketMonitor::~TcpSocketMonitor() {
    {
        std::lock_guard<std::mutex> guard(mLock);
        mIsRunning = false;
        mIsSuspended = true;
    }
    mCv.notify_all();
    mPollingThread.join();
}

}  // namespace net
}  // namespace android
