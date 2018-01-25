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

#ifndef _DNS_DNSTLSSOCKET_H
#define _DNS_DNSTLSSOCKET_H

#include <future>
#include <mutex>
#include <openssl/ssl.h>

#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>
#include <netdutils/Slice.h>
#include <netdutils/Status.h>

#include "dns/DnsTlsServer.h"
#include "dns/IDnsTlsSocket.h"

namespace android {
namespace net {

class DnsTlsSessionCache;

using netdutils::Slice;

// A class for managing a TLS socket that sends and receives messages in
// [length][value] format, with a 2-byte length (i.e. DNS-over-TCP format).
class DnsTlsSocket : public IDnsTlsSocket {
public:
    DnsTlsSocket(const DnsTlsServer& server, unsigned mark,
                 DnsTlsSessionCache* _Nonnull cache) :
            mMark(mark), mServer(server), mCache(cache) {}
    ~DnsTlsSocket();

    // Creates the SSL context for this session and connect.  Returns false on failure.
    // This method should be called after construction and before use of a DnsTlsSocket.
    // Only call this method once per DnsTlsSocket.
    bool initialize() EXCLUDES(mLock);

    // Send a query on the provided SSL socket.  |query| contains
    // the body of a query, not including the ID header. Returns the server's response.
    DnsTlsServer::Result query(uint16_t id, const Slice query) override;

private:
    // Lock to be held while performing a query.
    std::mutex mLock;

    // On success, sets mSslFd to a socket connected to mAddr (the
    // connection will likely be in progress if mProtocol is IPPROTO_TCP).
    // On error, returns the errno.
    netdutils::Status tcpConnect() REQUIRES(mLock);

    // Connect an SSL session on the provided socket.  If connection fails, closing the
    // socket remains the caller's responsibility.
    bssl::UniquePtr<SSL> sslConnect(int fd) REQUIRES(mLock);

    // Disconnect the SSL session and close the socket.
    void sslDisconnect() REQUIRES(mLock);

    // Writes a buffer to the socket.
    bool sslWrite(const Slice buffer) REQUIRES(mLock);

    // Reads exactly the specified number of bytes from the socket.  Blocking.
    // Returns false if the socket closes before enough bytes can be read.
    bool sslRead(const Slice buffer) REQUIRES(mLock);

    struct Query {
        uint16_t id;
        const Slice query;
    };

    bool sendQuery(const Query& q) REQUIRES(mLock);
    DnsTlsServer::Result readResponse() REQUIRES(mLock);

    // SSL Socket fields.
    bssl::UniquePtr<SSL_CTX> mSslCtx GUARDED_BY(mLock);
    base::unique_fd mSslFd GUARDED_BY(mLock);
    bssl::UniquePtr<SSL> mSsl GUARDED_BY(mLock);

    const unsigned mMark;  // Socket mark
    const DnsTlsServer mServer;
    DnsTlsSessionCache* _Nonnull const mCache;
};

}  // end of namespace net
}  // end of namespace android

#endif  // _DNS_DNSTLSSOCKET_H
