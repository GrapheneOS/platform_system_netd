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

#include "SoftapController.h"

#include <errno.h>
#include <string.h>

#include <vector>
#include <string>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>
#include <hardware_legacy/wifi.h>

#include "ResponseCode.h"

#define AP_BSS_START_DELAY_MICROSECONDS	200000
#define AP_BSS_STOP_DELAY_MICROSECONDS	500000

using android::wifi_system::HostapdManager;
using std::vector;
using std::string;

namespace {

vector<uint8_t> cstr2vector(const char* data) {
    return vector<uint8_t>(data, data + strlen(data));
}

}  // namespace

SoftapController::SoftapController() {
}

SoftapController::~SoftapController() {
}

int SoftapController::startSoftap() {
    if (!hostapd_manager_.StartHostapd()) {
        ALOGE("Failed to start SoftAP");
        return ResponseCode::OperationFailed;
    }

    ALOGD("SoftAP started successfully");
    usleep(AP_BSS_START_DELAY_MICROSECONDS);

    return ResponseCode::SoftapStatusResult;
}

int SoftapController::stopSoftap() {
    ALOGD("Stopping the SoftAP service...");

    if (!hostapd_manager_.StopHostapd()) {
      ALOGE("Failed to stop hostapd service!");
      // But what can we really do at this point?
    }

    ALOGD("SoftAP stopped successfully");
    usleep(AP_BSS_STOP_DELAY_MICROSECONDS);
    return ResponseCode::SoftapStatusResult;
}

bool SoftapController::isSoftapStarted() {
    return hostapd_manager_.IsHostapdRunning();
}

/*
 * Arguments:
 *  argv[2] - wlan interface
 *  argv[3] - SSID
 *  argv[4] - Broadcast/Hidden
 *  argv[5] - Channel
 *  argv[6] - Security
 *  argv[7] - Key
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
    if (argc < 5) {
        ALOGE("Softap set is missing arguments. Please use:");
        ALOGE("softap <wlan iface> <SSID> <hidden/broadcast> <channel> <wpa2?-psk|open> <passphrase>");
        return ResponseCode::CommandSyntaxError;
    }

    bool is_hidden = false;
    if (!strcasecmp(argv[4], "hidden"))
        is_hidden = true;

    int channel = -1;
    if (argc >= 5) {
        channel = atoi(argv[5]);
    }

    const char* passphrase = (argc > 7) ? argv[7] : nullptr;
    const char* security_type = (argc > 6) ? argv[6] : nullptr;
    HostapdManager::EncryptionType encryption_type =
        HostapdManager::EncryptionType::kOpen;
    vector<uint8_t> passphrase_bytes;
    if (security_type && passphrase && !strcmp(argv[6], "wpa-psk")) {
      encryption_type = HostapdManager::EncryptionType::kWpa;
      passphrase_bytes = cstr2vector(argv[7]);
    } else if (security_type && passphrase && !strcmp(argv[6], "wpa2-psk")) {
      encryption_type = HostapdManager::EncryptionType::kWpa2;
      passphrase_bytes = cstr2vector(argv[7]);
    }

    string config = hostapd_manager_.CreateHostapdConfig(
        argv[2],
        cstr2vector(argv[3]),
        is_hidden,
        channel,
        encryption_type,
        passphrase_bytes);

    if (!hostapd_manager_.WriteHostapdConfig(config)) {
        ALOGE("Cannot write to hostapd conf file: %s", strerror(errno));
        return ResponseCode::OperationFailed;
    }
    return ResponseCode::SoftapStatusResult;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or P2P or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    char *fwpath = NULL;

    if (argc < 4) {
        ALOGE("SoftAP fwreload is missing arguments. Please use: softap <wlan iface> <AP|P2P|STA>");
        return ResponseCode::CommandSyntaxError;
    }

    if (strcmp(argv[3], "AP") == 0) {
        fwpath = (char *)wifi_get_fw_path(WIFI_GET_FW_PATH_AP);
    } else if (strcmp(argv[3], "P2P") == 0) {
        fwpath = (char *)wifi_get_fw_path(WIFI_GET_FW_PATH_P2P);
    } else if (strcmp(argv[3], "STA") == 0) {
        fwpath = (char *)wifi_get_fw_path(WIFI_GET_FW_PATH_STA);
    } else {
        return ResponseCode::CommandParameterError;
    }
    if (!fwpath) {
        ALOGE("Softap fwReload - NULL path for %s", argv[3]);
        return ResponseCode::SoftapStatusResult;
    }
    if (wifi_change_fw_path((const char *)fwpath)) {
        ALOGE("Softap fwReload failed");
        return ResponseCode::OperationFailed;
    }
    else {
        ALOGD("Softap fwReload - Ok");
    }
    return ResponseCode::SoftapStatusResult;
}
