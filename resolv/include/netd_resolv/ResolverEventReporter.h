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

#ifndef NETD_RESOLV_EVENT_REPORTER_H
#define NETD_RESOLV_EVENT_REPORTER_H

#include "aidl/android/net/metrics/INetdEventListener.h"

/*
 * This class can be used to get the binder reference to the netd events listener service
 * via stable runtime ABI which is achieved from libbinder_ndk.
 */
class ResolverEventReporter {
  public:
    // Returns the binder from the singleton ResolverEventReporter. This method is threadsafe.
    static std::shared_ptr<aidl::android::net::metrics::INetdEventListener> getListener();

  private:
    // Get netd events listener binder.
    ResolverEventReporter();

    std::shared_ptr<aidl::android::net::metrics::INetdEventListener> mListener;
};

#endif  // NETD_RESOLV_EVENT_REPORTER_H
