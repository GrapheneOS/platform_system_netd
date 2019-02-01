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

#include "EventReporter.h"

using android::interface_cast;
using android::net::INetdUnsolicitedEventListener;
using android::net::metrics::INetdEventListener;

android::sp<INetdEventListener> EventReporter::getNetdEventListener() {
    std::lock_guard lock(mEventMutex);
    if (mNetdEventListener == nullptr) {
        // Use checkService instead of getService because getService waits for 5 seconds for the
        // service to become available. The DNS resolver inside netd is started much earlier in the
        // boot sequence than the framework DNS listener, and we don't want to delay all DNS lookups
        // for 5 seconds until the DNS listener starts up.
        android::sp<android::IBinder> b = android::defaultServiceManager()->checkService(
                android::String16("netd_listener"));
        mNetdEventListener = interface_cast<INetdEventListener>(b);
    }
    // If the netd listener service is dead, the binder call will just return an error, which should
    // be fine because the only impact is that we can't log netd events. In any case, this should
    // only happen if the system server is going down, which means it will shortly be taking us down
    // with it.
    return mNetdEventListener;
}

EventReporter::UnsolListeners EventReporter::getNetdUnsolicitedEventListeners() {
    std::lock_guard lock(mUnsolicitedMutex);
    return mUnsolListeners;
}

void EventReporter::registerUnsolEventListener(
        const android::sp<INetdUnsolicitedEventListener>& listener) {
    std::lock_guard lock(mUnsolicitedMutex);
    mUnsolListeners.insert(listener);

    // Create the death listener.
    class DeathRecipient : public android::IBinder::DeathRecipient {
      public:
        DeathRecipient(UnsolListeners* listeners,
                       android::sp<INetdUnsolicitedEventListener> listener, std::mutex& unsolMutex)
            : mMutex(unsolMutex), mUnsolListeners(listeners), mListener(std::move(listener)) {}
        ~DeathRecipient() override = default;

      private:
        void binderDied(const android::wp<android::IBinder>& /* who */) override {
            std::lock_guard lock(mMutex);
            mUnsolListeners->erase(mListener);
        }

        std::mutex& mMutex;
        UnsolListeners* mUnsolListeners GUARDED_BY(mMutex);
        android::sp<INetdUnsolicitedEventListener> mListener;
    };
    android::sp<android::IBinder::DeathRecipient> deathRecipient =
            new DeathRecipient(&mUnsolListeners, listener, mUnsolicitedMutex);
    android::IInterface::asBinder(listener)->linkToDeath(deathRecipient);
}
