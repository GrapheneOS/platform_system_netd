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
 */

#define LOG_TAG "Netd"
#include <cutils/log.h>

#include "Controllers.h"
#include "IdletimerController.h"
#include "NetworkController.h"
#include "RouteController.h"
#include "Stopwatch.h"
#include "oem_iptables_hook.h"

namespace android {
namespace net {

namespace {
/**
 * List of module chains to be created, along with explicit ordering. ORDERING
 * IS CRITICAL, AND SHOULD BE TRIPLE-CHECKED WITH EACH CHANGE.
 */
static const char* FILTER_INPUT[] = {
        // Bandwidth should always be early in input chain, to make sure we
        // correctly count incoming traffic against data plan.
        BandwidthController::LOCAL_INPUT,
        FirewallController::LOCAL_INPUT,
        NULL,
};

static const char* FILTER_FORWARD[] = {
        OEM_IPTABLES_FILTER_FORWARD,
        FirewallController::LOCAL_FORWARD,
        BandwidthController::LOCAL_FORWARD,
        NatController::LOCAL_FORWARD,
        NULL,
};

static const char* FILTER_OUTPUT[] = {
        OEM_IPTABLES_FILTER_OUTPUT,
        FirewallController::LOCAL_OUTPUT,
        StrictController::LOCAL_OUTPUT,
        BandwidthController::LOCAL_OUTPUT,
        NULL,
};

static const char* RAW_PREROUTING[] = {
        BandwidthController::LOCAL_RAW_PREROUTING,
        IdletimerController::LOCAL_RAW_PREROUTING,
        NatController::LOCAL_RAW_PREROUTING,
        NULL,
};

static const char* MANGLE_POSTROUTING[] = {
        BandwidthController::LOCAL_MANGLE_POSTROUTING,
        IdletimerController::LOCAL_MANGLE_POSTROUTING,
        NULL,
};

static const char* MANGLE_FORWARD[] = {
        NatController::LOCAL_MANGLE_FORWARD,
        NULL,
};

static const char* NAT_PREROUTING[] = {
        OEM_IPTABLES_NAT_PREROUTING,
        NULL,
};

static const char* NAT_POSTROUTING[] = {
        NatController::LOCAL_NAT_POSTROUTING,
        NULL,
};

static void createChildChains(IptablesTarget target, const char* table, const char* parentChain,
        const char** childChains) {
    const char** childChain = childChains;
    do {
        // Order is important:
        // -D to delete any pre-existing jump rule (removes references
        //    that would prevent -X from working)
        // -F to flush any existing chain
        // -X to delete any existing chain
        // -N to create the chain
        // -A to append the chain to parent

        execIptablesSilently(target, "-t", table, "-D", parentChain, "-j", *childChain, NULL);
        execIptablesSilently(target, "-t", table, "-F", *childChain, NULL);
        execIptablesSilently(target, "-t", table, "-X", *childChain, NULL);
        execIptables(target, "-t", table, "-N", *childChain, NULL);
        execIptables(target, "-t", table, "-A", parentChain, "-j", *childChain, NULL);
    } while (*(++childChain) != NULL);
}

}  // namespace

Controllers::Controllers() : clatdCtrl(&netCtrl) {
    InterfaceController::initializeAll();
    IptablesRestoreController::installSignalHandler(&iptablesRestoreCtrl);
}

void Controllers::initIptablesRules() {
    /*
     * This is the only time we touch top-level chains in iptables; controllers
     * should only mutate rules inside of their children chains, as created by
     * the constants above.
     *
     * Modules should never ACCEPT packets (except in well-justified cases);
     * they should instead defer to any remaining modules using RETURN, or
     * otherwise DROP/REJECT.
     */

    // Create chains for children modules
    Stopwatch s;
    createChildChains(V4V6, "filter", "INPUT", FILTER_INPUT);
    createChildChains(V4V6, "filter", "FORWARD", FILTER_FORWARD);
    createChildChains(V4V6, "filter", "OUTPUT", FILTER_OUTPUT);
    createChildChains(V4V6, "raw", "PREROUTING", RAW_PREROUTING);
    createChildChains(V4V6, "mangle", "POSTROUTING", MANGLE_POSTROUTING);
    createChildChains(V4V6, "mangle", "FORWARD", MANGLE_FORWARD);
    createChildChains(V4, "nat", "PREROUTING", NAT_PREROUTING);
    createChildChains(V4, "nat", "POSTROUTING", NAT_POSTROUTING);
    ALOGI("Creating child chains: %.1fms", s.getTimeAndReset());

    // Let each module setup their child chains
    setupOemIptablesHook();
    ALOGI("Setting up OEM hooks: %.1fms", s.getTimeAndReset());

    /* When enabled, DROPs all packets except those matching rules. */
    firewallCtrl.setupIptablesHooks();
    ALOGI("Setting up FirewallController hooks: %.1fms", s.getTimeAndReset());

    /* Does DROPs in FORWARD by default */
    natCtrl.setupIptablesHooks();
    ALOGI("Setting up NatController hooks: %.1fms", s.getTimeAndReset());

    /*
     * Does REJECT in INPUT, OUTPUT. Does counting also.
     * No DROP/REJECT allowed later in netfilter-flow hook order.
     */
    bandwidthCtrl.setupIptablesHooks();
    ALOGI("Setting up BandwidthController hooks: %.1fms", s.getTimeAndReset());

    /*
     * Counts in nat: PREROUTING, POSTROUTING.
     * No DROP/REJECT allowed later in netfilter-flow hook order.
     */
    idletimerCtrl.setupIptablesHooks();
    ALOGI("Setting up IdletimerController hooks: %.1fms", s.getTimeAndReset());
}

void Controllers::init() {
    initIptablesRules();

    Stopwatch s;
    bandwidthCtrl.enableBandwidthControl(false);
    ALOGI("Disabling bandwidth control: %.1fms", s.getTimeAndReset());

    if (int ret = RouteController::Init(NetworkController::LOCAL_NET_ID)) {
        ALOGE("failed to initialize RouteController (%s)", strerror(-ret));
    }
    ALOGI("Initializing RouteController: %.1fms", s.getTimeAndReset());
}

Controllers* gCtls = nullptr;

}  // namespace net
}  // namespace android
