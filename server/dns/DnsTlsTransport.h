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

#ifndef _DNS_DNSTLSTRANSPORT_H
#define _DNS_DNSTLSTRANSPORT_H

#include <netinet/in.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>

#include "android-base/unique_fd.h"

// Forward declaration.
typedef struct ssl_st SSL;

namespace android {
namespace net {

class DnsTlsTransport {
public:
    struct Server {
        // Default constructor
        Server() {}
        // Allow sockaddr_storage to be promoted to Server automatically.
        Server(const sockaddr_storage& ss) : ss(ss) {}
        sockaddr_storage ss;
        std::set<std::vector<uint8_t>> fingerprints;
        std::string name;
        int protocol = IPPROTO_TCP;
        // Exact comparison of Server objects
        bool operator <(const Server& other) const;
        bool operator ==(const Server& other) const;
    };

    enum class Response : uint8_t { success, network_error, limit_error, internal_error };

    // Given a |query| of length |qlen|, sends it to the server on the network indicated by |mark|,
    // and writes the response into |ans|, which can accept up to |anssiz| bytes.  Indicates
    // the number of bytes written in |resplen|.  If |resplen| is zero, an
    // error has occurred.
    static Response query(const Server& server, unsigned mark, const uint8_t *query, size_t qlen,
            uint8_t *ans, size_t anssiz, int *resplen);

    // Check that a given TLS server is fully working on the specified netid, and has the
    // provided SHA-256 fingerprint (if nonempty).  This function is used in ResolverController
    // to ensure that we don't enable DNS over TLS on networks where it doesn't actually work.
    static bool validate(const Server& server, unsigned netid);

private:
    DnsTlsTransport(const Server& server, unsigned mark)
            : mMark(mark), mServer(server)
            {}
    ~DnsTlsTransport() {}

    Response doQuery(const uint8_t *query, size_t qlen, uint8_t *ans, size_t anssiz, int *resplen);

    // On success, returns a non-blocking socket connected to mAddr (the
    // connection will likely be in progress if mProtocol is IPPROTO_TCP).
    // On error, returns -1 with errno set appropriately.
    android::base::unique_fd makeConnectedSocket() const;

    SSL* sslConnect(int fd);

    // Writes a buffer to the socket.
    bool sslWrite(int fd, SSL *ssl, const uint8_t *buffer, int len);

    // Reads exactly the specified number of bytes from the socket.  Blocking.
    // Returns false if the socket closes before enough bytes can be read.
    bool sslRead(int fd, SSL *ssl, uint8_t *buffer, int len);

    const unsigned mMark;  // Socket mark
    const Server mServer;
};

// This comparison ignores ports, names, and fingerprints.
struct AddressComparator {
    bool operator() (const DnsTlsTransport::Server& x, const DnsTlsTransport::Server& y) const;
};


}  // namespace net
}  // namespace android

#endif  // _DNS_DNSTLSTRANSPORT_H
