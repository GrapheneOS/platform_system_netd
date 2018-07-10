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

#include <gtest/gtest.h>

#include "netdutils/Log.h"

android::netdutils::LogEntry globalFunctionName() {
    return android::netdutils::LogEntry().function(__FUNCTION__);
}

android::netdutils::LogEntry globalPrettyFunctionName() {
    return android::netdutils::LogEntry().prettyFunction(__PRETTY_FUNCTION__);
}

namespace android {
namespace netdutils {

namespace {

LogEntry functionName() {
    return LogEntry().function(__FUNCTION__);
}

LogEntry prettyFunctionName() {
    return LogEntry().prettyFunction(__PRETTY_FUNCTION__);
}

}  // namespace

class AAA {
  public:
    AAA() = default;

    LogEntry functionName() {
        return LogEntry().function(__FUNCTION__);
    }

    LogEntry prettyFunctionName() {
        return LogEntry().prettyFunction(__PRETTY_FUNCTION__);
    }

    class BBB {
      public:
        BBB() = default;

        LogEntry functionName() {
            return LogEntry().function(__FUNCTION__);
        }

        LogEntry prettyFunctionName() {
            return LogEntry().prettyFunction(__PRETTY_FUNCTION__);
        }
    };
};

TEST(LogEntryTest, Empty) {
    LogEntry empty;
    EXPECT_EQ("", empty.toString());
}

TEST(LogEntryTest, GlobalFunction) {
    EXPECT_EQ("globalFunctionName()", ::globalFunctionName().toString());
}

TEST(LogEntryTest, GlobalPrettyFunction) {
    EXPECT_EQ("globalPrettyFunctionName()", ::globalPrettyFunctionName().toString());
}

TEST(LogEntryTest, UnnamedNamespaceFunction) {
    const LogEntry entry = functionName();
    EXPECT_EQ("functionName()", entry.toString());
}

TEST(LogEntryTest, UnnamedNamespacePrettyFunction) {
    const LogEntry entry = prettyFunctionName();
    EXPECT_EQ("prettyFunctionName()", entry.toString());
}

TEST(LogEntryTest, ClassFunction) {
    const LogEntry entry = AAA().functionName();
    EXPECT_EQ("functionName()", entry.toString());
}

TEST(LogEntryTest, ClassPrettyFunction) {
    const LogEntry entry = AAA().prettyFunctionName();
    EXPECT_EQ("AAA::prettyFunctionName()", entry.toString());
}

TEST(LogEntryTest, InnerClassFunction) {
    const LogEntry entry = AAA::BBB().functionName();
    EXPECT_EQ("functionName()", entry.toString());
}

TEST(LogEntryTest, InnerClassPrettyFunction) {
    const LogEntry entry = AAA::BBB().prettyFunctionName();
    EXPECT_EQ("BBB::prettyFunctionName()", entry.toString());
}

}  // namespace netdutils
}  // namespace android
