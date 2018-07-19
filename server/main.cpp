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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <mutex>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <dirent.h>

#define LOG_TAG "Netd"

#include "log/log.h"

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>

#include "CommandListener.h"
#include "Controllers.h"
#include "DnsProxyListener.h"
#include "FwmarkServer.h"
#include "MDnsSdListener.h"
#include "NFLogListener.h"
#include "NetdConstants.h"
#include "NetdHwService.h"
#include "NetdNativeService.h"
#include "NetlinkManager.h"
#include "Process.h"
#include "Stopwatch.h"

using android::status_t;
using android::sp;
using android::IPCThreadState;
using android::ProcessState;
using android::defaultServiceManager;
using android::net::CommandListener;
using android::net::DnsProxyListener;
using android::net::FwmarkServer;
using android::net::NetdHwService;
using android::net::NetdNativeService;
using android::net::NetlinkManager;
using android::net::NFLogListener;
using android::net::makeNFLogListener;

const char* const PID_FILE_PATH = "/data/misc/net/netd_pid";

std::mutex android::net::gBigNetdLock;

int main() {
    using android::net::gLog;
    using android::net::gCtls;
    Stopwatch s;
    gLog.info("netd 1.0 starting");

    android::net::process::removePidFile(PID_FILE_PATH);
    android::net::process::blockSigPipe();

    // Before we do anything that could fork, mark CLOEXEC the UNIX sockets that we get from init.
    // FrameworkListener does this on initialization as well, but we only initialize these
    // components after having initialized other subsystems that can fork.
    for (const auto& sock : { CommandListener::SOCKET_NAME,
                              DnsProxyListener::SOCKET_NAME,
                              FwmarkServer::SOCKET_NAME,
                              MDnsSdListener::SOCKET_NAME }) {
        setCloseOnExec(sock);
    }

    NetlinkManager *nm = NetlinkManager::Instance();
    if (nm == nullptr) {
        ALOGE("Unable to create NetlinkManager");
        exit(1);
    };

    gCtls = new android::net::Controllers();
    gCtls->init();

    CommandListener cl;
    nm->setBroadcaster((SocketListener *) &cl);

    if (nm->start()) {
        ALOGE("Unable to start NetlinkManager (%s)", strerror(errno));
        exit(1);
    }

    std::unique_ptr<NFLogListener> logListener;
    {
        auto result = makeNFLogListener();
        if (!isOk(result)) {
            ALOGE("Unable to create NFLogListener: %s", toString(result).c_str());
            exit(1);
        }
        logListener = std::move(result.value());
        auto status = gCtls->wakeupCtrl.init(logListener.get());
        if (!isOk(result)) {
            gLog.error("Unable to init WakeupController: %s", toString(result).c_str());
            // We can still continue without wakeup packet logging.
        }
    }

    // Set local DNS mode, to prevent bionic from proxying
    // back to this service, recursively.
    setenv("ANDROID_DNS_MODE", "local", 1);
    DnsProxyListener dpl(&gCtls->netCtrl, &gCtls->eventReporter);
    if (dpl.startListener()) {
        ALOGE("Unable to start DnsProxyListener (%s)", strerror(errno));
        exit(1);
    }

    MDnsSdListener mdnsl;
    if (mdnsl.startListener()) {
        ALOGE("Unable to start MDnsSdListener (%s)", strerror(errno));
        exit(1);
    }

    FwmarkServer fwmarkServer(&gCtls->netCtrl, &gCtls->eventReporter, &gCtls->trafficCtrl);
    if (fwmarkServer.startListener()) {
        ALOGE("Unable to start FwmarkServer (%s)", strerror(errno));
        exit(1);
    }

    Stopwatch subTime;
    status_t ret;
    if ((ret = NetdNativeService::start()) != android::OK) {
        ALOGE("Unable to start NetdNativeService: %d", ret);
        exit(1);
    }
    gLog.info("Registering NetdNativeService: %.1fms", subTime.getTimeAndReset());

    /*
     * Now that we're up, we can respond to commands. Starting the listener also tells
     * NetworkManagementService that we are up and that our binder interface is ready.
     */
    if (cl.startListener()) {
        ALOGE("Unable to start CommandListener (%s)", strerror(errno));
        exit(1);
    }
    gLog.info("Starting CommandListener: %.1fms", subTime.getTimeAndReset());

    android::net::process::ScopedPidFile pidFile(PID_FILE_PATH);

    // Now that netd is ready to process commands, advertise service
    // availability for HAL clients.
    NetdHwService mHwSvc;
    if ((ret = mHwSvc.start()) != android::OK) {
        ALOGE("Unable to start NetdHwService: %d", ret);
        exit(1);
    }
    gLog.info("Registering NetdHwService: %.1fms", subTime.getTimeAndReset());

    gLog.info("Netd started in %dms", static_cast<int>(s.timeTaken()));

    IPCThreadState::self()->joinThreadPool();

    gLog.info("netd exiting");

    exit(0);
}
