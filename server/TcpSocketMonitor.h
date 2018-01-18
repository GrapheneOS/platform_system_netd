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

#ifndef TCP_SOCKET_MONITOR_H
#define TCP_SOCKET_MONITOR_H

#include <chrono>
#include <condition_variable>
#include <mutex>

#include <android-base/thread_annotations.h>
#include "utils/String16.h"

namespace android {
namespace net {

class DumpWriter;

class TcpSocketMonitor {
  public:
    static const String16 DUMP_KEYWORD;
    static const std::chrono::milliseconds kDefaultPollingInterval;

    TcpSocketMonitor();
    ~TcpSocketMonitor();

    void dump(DumpWriter& dw);
    void setPollingInterval(std::chrono::milliseconds duration);
    void resumePolling();
    void suspendPolling();

  private:
    void poll();
    void waitForNextPoll();
    bool isRunning();

    // Lock guarding all reads and writes to member variables.
    std::mutex mLock;
    // Used by the polling thread for sleeping between poll operations.
    std::condition_variable mCv;
    // The duration of a sleep between polls. Can be updated by the instance owner for dynamically
    // adjusting the polling rate.
    std::chrono::milliseconds mNextSleepDurationMs GUARDED_BY(mLock);
    // The time of the last successful poll operation.
    std::chrono::time_point<std::chrono::steady_clock> mLastPoll GUARDED_BY(mLock);
    // True if the polling thread should sleep until notified.
    bool mIsSuspended GUARDED_BY(mLock);
    // True while the polling thread should poll.
    bool mIsRunning GUARDED_BY(mLock);
    std::thread mPollingThread;
};

}  // namespace net
}  // namespace android

#endif /* TCP_SOCKET_MONITOR_H */
