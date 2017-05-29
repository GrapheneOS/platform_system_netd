/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef NETUTILS_STATUS_H
#define NETUTILS_STATUS_H

#include <cassert>
#include <ostream>

namespace android {
namespace netdutils {

// Simple status implementation suitable for use on the stack in low
// or moderate performance code. This can definitely be improved but
// for now short string optimization is expected to keep the common
// success case fast.
class Status {
  public:
    Status() = default;

    Status(int code) : mCode(code) {}

    Status(int code, const std::string& msg) : mCode(code), mMsg(msg) { assert(!ok()); }

    int code() const { return mCode; }

    bool ok() const { return code() == 0; }

    const std::string& msg() const { return mMsg; }

    bool operator==(const Status& other) const {
        return (code() == other.code()) && (msg() == other.msg());
    }
    bool operator!=(const Status& other) const { return !(*this == other); }

  private:
    int mCode = 0;
    std::string mMsg;
};

namespace status {

const Status ok{0};
const Status eof{256, "end of file"};
const Status undefined{std::numeric_limits<int>::max(), "undefined"};

}  // namespace status

// Return true if status is "OK". This is sometimes preferable to
// status.ok() when we want to check the state of Status-like objects
// that implicitly cast to Status.
inline bool isOk(const Status status) {
    return status.ok();
}

// Document that status is expected to be ok. This function may log
// (or assert when running in debug mode) if status has an unexpected
// value.
void expectOk(const Status status);

// Convert POSIX errno to a Status object.
// If Status is extended to have more features, this mapping may
// become more complex.
//
// TODO: msg is only a placeholder for now
Status statusFromErrno(int err, const std::string& msg);

std::string toString(const Status status);

std::ostream& operator<<(std::ostream& os, const Status& s);

#define RETURN_IF_NOT_OK_IMPL(tmp, stmt)           \
    do {                                           \
        ::android::netdutils::Status tmp = (stmt); \
        if (!isOk(tmp)) {                          \
            return tmp;                            \
        }                                          \
    } while (false)

#define RETURN_IF_NOT_OK_CONCAT(line, stmt) RETURN_IF_NOT_OK_IMPL(__CONCAT(_status_, line), stmt)

// Macro to allow exception-like handling of error return values.
//
// If the evaluation of stmt results in an error, return that error
// from current function.
//
// Example usage:
// Status bar() { ... }
//
// RETURN_IF_NOT_OK(status);
// RETURN_IF_NOT_OK(bar());
#define RETURN_IF_NOT_OK(stmt) RETURN_IF_NOT_OK_CONCAT(__LINE__, stmt)

}  // namespace netdutils
}  // namespace android

#endif /* NETUTILS_STATUS_H */
