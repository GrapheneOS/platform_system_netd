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

#ifndef _DNS_IDNSTLSSOCKET_H
#define _DNS_IDNSTLSSOCKET_H

#include <cstdint>
#include <cstddef>

#include <netdutils/Slice.h>

#include "dns/DnsTlsServer.h"

namespace android {
namespace net {

class IDnsTlsSocketObserver;
class DnsTlsSessionCache;

// A class for managing a TLS socket that sends and receives messages in
// [length][value] format, with a 2-byte length (i.e. DNS-over-TCP format).
class IDnsTlsSocket {
public:
    virtual ~IDnsTlsSocket() {};
    // Send a query on the provided SSL socket.  |query| contains
    // the body of a query, not including the ID bytes.  Returns the server's response.
    virtual DnsTlsServer::Result query(uint16_t id, const netdutils::Slice query) = 0;
};

}  // end of namespace net
}  // end of namespace android

#endif  // _DNS_IDNSTLSSOCKET_H
