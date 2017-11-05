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

#include <deque>
#include <mutex>
#include <openssl/ssl.h>

#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>

#include "dns/DnsTlsServer.h"

namespace android {
namespace net {

class DnsTlsTransport {
public:
    DnsTlsTransport(const DnsTlsServer& server, unsigned mark)
            : mMark(mark), mServer(server)
            {}
    ~DnsTlsTransport() {}

    // Creates the SSL context for this session.  Returns false on failure.
    // This method should be called after construction and before use of a DnsTlsTransport.
    bool initialize();
    
    enum class Response : uint8_t { success, network_error, limit_error, internal_error };

    // Given a |query| of length |qlen|, this method sends it to the server
    // and writes the response into |ans|, which can accept up to |anssiz| bytes.
    // The number of bytes is written to |resplen|.  If |resplen| is zero, an
    // error has occurred.
    Response query(const uint8_t *query, size_t qlen,
            uint8_t *ans, size_t anssiz, int *resplen);

    // Check that a given TLS server is fully working on the specified netid, and has the
    // provided SHA-256 fingerprint (if nonempty).  This function is used in ResolverController
    // to ensure that we don't enable DNS over TLS on networks where it doesn't actually work.
    static bool validate(const DnsTlsServer& server, unsigned netid);

private:
    // Send a query on the provided SSL socket.
    Response sendQuery(int fd, SSL* ssl, const uint8_t *query, size_t qlen);

    // Wait for the response to |query| on |ssl|, and write it to |ans|, an output buffer
    // of size |anssiz|.  If |resplen| is zero, the read failed.
    Response readResponse(int fd, SSL* ssl, const uint8_t *query,
        uint8_t *ans, size_t anssiz, int *resplen);

    // On success, returns a non-blocking socket connected to mAddr (the
    // connection will likely be in progress if mProtocol is IPPROTO_TCP).
    // On error, returns -1 with errno set appropriately.
    base::unique_fd makeConnectedSocket() const;

    // Connect an SSL session on the provided socket.  If connection fails, closing the
    // socket remains the caller's responsibility.
    bssl::UniquePtr<SSL> sslConnect(int fd);

    // Disconnect the SSL session and close the socket.
    void sslDisconnect(bssl::UniquePtr<SSL> ssl, base::unique_fd fd);

    // Writes a buffer to the socket.
    bool sslWrite(int fd, SSL *ssl, const uint8_t *buffer, int len);

    // Reads exactly the specified number of bytes from the socket.  Blocking.
    // Returns false if the socket closes before enough bytes can be read.
    bool sslRead(int fd, SSL *ssl, uint8_t *buffer, int len);

    // Using SSL_CTX to create new SSL objects is thread-safe, so this object does not
    // require a lock annotation.
    bssl::UniquePtr<SSL_CTX> mSslCtx;

    const unsigned mMark;  // Socket mark
    const DnsTlsServer mServer;

    // Cache of recently seen SSL_SESSIONs.  This is used to support session tickets.
    static int newSessionCallback(SSL* ssl, SSL_SESSION* session);
    void recordSession(SSL_SESSION* session);
    static void removeSessionCallback(SSL_CTX* ssl_ctx, SSL_SESSION* session);
    void removeSession(SSL_SESSION* session);
    std::mutex mLock;
    std::deque<bssl::UniquePtr<SSL_SESSION>> mSessions GUARDED_BY(mLock);
};

}  // namespace net
}  // namespace android

#endif  // _DNS_DNSTLSTRANSPORT_H
