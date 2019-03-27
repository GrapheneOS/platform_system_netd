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
#define LOG_TAG "ResolverEventReporter"

#include <android-base/logging.h>
#include <android/binder_manager.h>

#include "ResolverEventReporter.h"

using aidl::android::net::metrics::INetdEventListener;

ResolverEventReporter& ResolverEventReporter::getInstance() {
    // It should be initialized only once.
    static ResolverEventReporter instance;

    // Add default listener which comes from framework. The framework listener "netd_listener"
    // should be added only once if it has been added successfully.
    // TODO: Consider registering default listener from framework.
    // Currently, the framework listener "netd_listener" is shared by netd and libnetd_resolv.
    // Consider breaking it into two listeners. Once it has done, may let framework register
    // the listener proactively.
    instance.addDefaultListener();

    return instance;
}

ResolverEventReporter::ListenerSet ResolverEventReporter::getListeners() const {
    return getListenersImpl();
}

int ResolverEventReporter::addListener(const std::shared_ptr<INetdEventListener>& listener) {
    return addListenerImpl(listener);
}

void ResolverEventReporter::addDefaultListener() {
    std::lock_guard lock(mMutex);

    static bool added = false;
    if (added) return;

    // Use the non-blocking call AServiceManager_checkService in order not to delay DNS
    // lookup threads when the netd_listener service is not ready.
    ndk::SpAIBinder binder = ndk::SpAIBinder(AServiceManager_checkService("netd_listener"));
    std::shared_ptr<INetdEventListener> listener = INetdEventListener::fromBinder(binder);

    if (listener == nullptr) return;

    if (!addListenerImplLocked(listener)) added = true;
}

void ResolverEventReporter::handleBinderDied() {
    std::lock_guard lock(mMutex);

    for (const auto& it : mListeners) {
        // TODO: Considering that find a way to identify dead binder if binder ndk has supported.
        // b/128712772.
        // Currently, binder ndk doesn't pass dead binder pointer to death handle function as
        // IBinder.DeathRecipient binderDied() does. The death handle function doesn't directly
        // know which binder was dead. This is a workaround which just removes the first found dead
        // binder in map. It doesn't guarantee that the first found dead binder is the real death
        // trigger. It should be okay sa far because this death handle function is only used for
        // the listener which registers from unit test and there has only one listener unit test
        // case now. In normal case, Netd should be killed if framework is dead. Don't need to
        // handle the death of framework listener. For long term, this should be fixed.
        if (!AIBinder_isAlive(it->asBinder().get())) {
            mListeners.erase(it);
            return;
        }
    }
}

ResolverEventReporter::ListenerSet ResolverEventReporter::getListenersImpl() const {
    std::lock_guard lock(mMutex);
    return mListeners;
}

int ResolverEventReporter::addListenerImpl(const std::shared_ptr<INetdEventListener>& listener) {
    std::lock_guard lock(mMutex);
    return addListenerImplLocked(listener);
}

int ResolverEventReporter::addListenerImplLocked(
        const std::shared_ptr<INetdEventListener>& listener) {
    if (listener == nullptr) {
        LOG(ERROR) << "The listener should not be null";
        return -EINVAL;
    }

    // TODO: Perhaps ignore the listener which has the same binder.
    const auto& it = mListeners.find(listener);
    if (it != mListeners.end()) {
        LOG(WARNING) << "The listener was already subscribed";
        return -EEXIST;
    }

    if (mDeathRecipient == nullptr) {
        // The AIBinder_DeathRecipient object is used to manage all death recipients for multiple
        // binder objects. It doesn't released because there should have at least one binder object
        // from framework.
        // TODO: Considering to remove death recipient for the binder object from framework because
        // it doesn't need death recipient actually.
        mDeathRecipient = AIBinder_DeathRecipient_new([](void* cookie) {
            auto onDeath = static_cast<ResolverEventReporter::OnDeathFunc*>(cookie);
            (*onDeath)();
        });
    }

    binder_status_t status = AIBinder_linkToDeath(listener->asBinder().get(), mDeathRecipient,
                                                  static_cast<void*>(&mOnDeath));
    if (STATUS_OK != status) {
        LOG(ERROR) << "Failed to register death notification for INetdEventListener";
        return -EAGAIN;
    }

    mListeners.insert(listener);
    return 0;
}