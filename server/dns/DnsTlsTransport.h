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
#include <memory>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>

#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>

// Forward declaration.
typedef struct ssl_st SSL;

namespace android {
namespace net {

class DnsTlsTransport {
public:
    ~DnsTlsTransport() {}
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

    // Cache of reusable DnsTlsTransports.  Transports stay in cache as long as
    // they are in use and for a few minutes after.
    // The key is a (netid, server) pair.  The netid is first for lexicographic comparison speed.
    typedef std::pair<unsigned, const Server> Key;
    static std::mutex sLock;
    static std::map<Key, std::unique_ptr<DnsTlsTransport>> sStore GUARDED_BY(sLock);
    static std::chrono::time_point<std::chrono::steady_clock> sLastCleanup GUARDED_BY(sLock);
    static void cleanup(std::chrono::time_point<std::chrono::steady_clock> now) REQUIRES(sLock);

    // Creates the SSL context for this transport.  Returns false on failure.
    bool initialize() REQUIRES(sLock);

    Response doQuery(const uint8_t *query, size_t qlen, uint8_t *ans, size_t anssiz, int *resplen);
    Response sendQuery(int fd, SSL* ssl, const uint8_t *query, size_t qlen);
    Response readResponse(int fd, SSL* ssl, const uint8_t *query, uint8_t *ans, size_t anssiz,
            int *resplen);

    // On success, returns a non-blocking socket connected to mAddr (the
    // connection will likely be in progress if mProtocol is IPPROTO_TCP).
    // On error, returns -1 with errno set appropriately.
    android::base::unique_fd makeConnectedSocket() const;

    bssl::UniquePtr<SSL> sslConnect(int fd);
    void sslDisconnect(bssl::UniquePtr<SSL> ssl, base::unique_fd fd);

    // Writes a buffer to the socket.
    bool sslWrite(int fd, SSL *ssl, const uint8_t *buffer, int len);

    // Reads exactly the specified number of bytes from the socket.  Blocking.
    // Returns false if the socket closes before enough bytes can be read.
    bool sslRead(int fd, SSL *ssl, uint8_t *buffer, int len);

    // There is a 1:1:1 correspondence between Key, DnsTlsTransport, and SSL_CTX.
    // Using SSL_CTX to create new SSL objects is thread-safe.
    bssl::UniquePtr<SSL_CTX> mSslCtx;

    const unsigned mMark;  // Socket mark
    const Server mServer;

    // Cache of recently seen SSL_SESSIONs.  This is used to support session tickets.
    static int newSessionCallback(SSL* ssl, SSL_SESSION* session);
    void recordSession(SSL_SESSION* session);
    static void removeSessionCallback(SSL_CTX* ssl_ctx, SSL_SESSION* session);
    void removeSession(SSL_SESSION* session);
    std::deque<bssl::UniquePtr<SSL_SESSION>> mSessions GUARDED_BY(sLock);

    // This use counter and timestamp are used to ensure that only idle transports are
    // destroyed.
    int mUseCount GUARDED_BY(sLock) = 0;
    std::chrono::time_point<std::chrono::steady_clock> mLastUsed GUARDED_BY(sLock);
};

// This comparison ignores ports, names, and fingerprints.
struct AddressComparator {
    bool operator() (const DnsTlsTransport::Server& x, const DnsTlsTransport::Server& y) const;
};


}  // namespace net
}  // namespace android

#endif  // _DNS_DNSTLSTRANSPORT_H
