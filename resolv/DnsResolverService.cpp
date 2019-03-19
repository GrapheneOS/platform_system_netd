/**
 * Copyright (c) 2019, The Android Open Source Project
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

#define LOG_TAG "DnsResolverService"

#include "DnsResolverService.h"

#include <set>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>  // AID_SYSTEM

#include "DnsResolver.h"
#include "NetdPermissions.h"  // PERM_*

using android::base::Join;
using android::base::StringPrintf;

namespace android {
namespace net {

namespace {

#define ENFORCE_ANY_PERMISSION(...)                                      \
    do {                                                                 \
        ::ndk::ScopedAStatus status = checkAnyPermission({__VA_ARGS__}); \
        if (!status.isOk()) {                                            \
            return status;                                               \
        }                                                                \
    } while (0)

#define ENFORCE_INTERNAL_PERMISSIONS() \
    ENFORCE_ANY_PERMISSION(PERM_CONNECTIVITY_INTERNAL, PERM_MAINLINE_NETWORK_STACK)

#define ENFORCE_NETWORK_STACK_PERMISSIONS() \
    ENFORCE_ANY_PERMISSION(PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK)

}  // namespace

binder_status_t DnsResolverService::start() {
    // TODO: Add disableBackgroundScheduling(true) after libbinder_ndk support it. b/126506010
    // NetdNativeService does call disableBackgroundScheduling currently, so it is fine now.
    DnsResolverService* resolverService = new DnsResolverService();
    binder_status_t status =
            AServiceManager_addService(resolverService->asBinder().get(), getServiceName());
    if (status != STATUS_OK) {
        return status;
    }

    ABinderProcess_startThreadPool();

    // TODO: register log callback if binder NDK backend support it. b/126501406

    return STATUS_OK;
}

::ndk::ScopedAStatus DnsResolverService::isAlive(bool* alive) {
    ENFORCE_INTERNAL_PERMISSIONS();

    *alive = true;

    return ::ndk::ScopedAStatus(AStatus_newOk());
}

::ndk::ScopedAStatus DnsResolverService::checkAnyPermission(
        const std::vector<const char*>& permissions) {
    // TODO: Remove callback and move this to unnamed namespace after libbiner_ndk supports
    // check_permission.
    if (!gResNetdCallbacks.check_calling_permission) {
        return ::ndk::ScopedAStatus(AStatus_fromExceptionCodeWithMessage(
                EX_NULL_POINTER, "check_calling_permission is null"));
    }
    pid_t pid = AIBinder_getCallingPid();
    uid_t uid = AIBinder_getCallingUid();

    // If the caller is the system UID, don't check permissions.
    // Otherwise, if the system server's binder thread pool is full, and all the threads are
    // blocked on a thread that's waiting for us to complete, we deadlock. http://b/69389492
    //
    // From a security perspective, there is currently no difference, because:
    // 1. The only permissions we check in netd's binder interface are CONNECTIVITY_INTERNAL
    //    and NETWORK_STACK, which the system server always has (or MAINLINE_NETWORK_STACK, which
    //    is equivalent to having both CONNECTIVITY_INTERNAL and NETWORK_STACK).
    // 2. AID_SYSTEM always has all permissions. See ActivityManager#checkComponentPermission.
    if (uid == AID_SYSTEM) {
        return ::ndk::ScopedAStatus(AStatus_newOk());
    }

    for (const char* permission : permissions) {
        if (gResNetdCallbacks.check_calling_permission(permission)) {
            return ::ndk::ScopedAStatus(AStatus_newOk());
        }
    }

    auto err = StringPrintf("UID %d / PID %d does not have any of the following permissions: %s",
                            uid, pid, Join(permissions, ',').c_str());
    return ::ndk::ScopedAStatus(AStatus_fromExceptionCodeWithMessage(EX_SECURITY, err.c_str()));
}

}  // namespace net
}  // namespace android
