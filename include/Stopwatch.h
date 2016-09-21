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

#ifndef NETD_INCLUDE_STOPWATCH_H
#define NETD_INCLUDE_STOPWATCH_H

#include <chrono>

class Stopwatch {
public:
    Stopwatch() : mStart(std::chrono::steady_clock::now()) {}
    virtual ~Stopwatch() {};

    float timeTaken() const {
        using ms = std::chrono::duration<float, std::ratio<1, 1000>>;
        return (std::chrono::duration_cast<ms>(
                std::chrono::steady_clock::now() - mStart)).count();
    }

private:
    std::chrono::time_point<std::chrono::steady_clock> mStart;
};

#endif  // NETD_INCLUDE_STOPWATCH_H
