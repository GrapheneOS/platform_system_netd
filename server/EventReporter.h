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

#ifndef NETD_SERVER_EVENT_REPORTER_H
#define NETD_SERVER_EVENT_REPORTER_H

#include <atomic>
#include <binder/IServiceManager.h>

#include "android/net/metrics/INetdEventListener.h"

/*
 * This class stores the reporting level and can be used to get the event listener service.
 */
class EventReporter {
public:
    int setMetricsReportingLevel(const int level);
    int getMetricsReportingLevel() const;

    // Returns the binder reference to the netd events listener service, attempting to fetch it if
    // we do not have it already. This method mutates internal state without taking a lock and must
    // only be called on one thread. This is safe because we only call this in the runCommand
    // methods of our commands, which are only called by FrameworkListener::onDataAvailable, which
    // is only called from SocketListener::runListener, which is a single-threaded select loop.
    android::sp<android::net::metrics::INetdEventListener> getNetdEventListener();

private:
    std::atomic_int mReportingLevel{
            android::net::metrics::INetdEventListener::REPORTING_LEVEL_METRICS};
    android::sp<android::net::metrics::INetdEventListener> mNetdEventListener;

};

#endif  // NETD_SERVER_EVENT_REPORTER_H
