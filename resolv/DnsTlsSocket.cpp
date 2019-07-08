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

#define LOG_TAG "resolv"

#include "DnsTlsSocket.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <linux/tcp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <unistd.h>
#include <algorithm>

#include "DnsTlsSessionCache.h"
#include "IDnsTlsSocketObserver.h"

#include <Fwmark.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "netdutils/SocketOption.h"
#include "private/android_filesystem_config.h"  // AID_DNS

namespace android {

using netdutils::enableSockopt;
using netdutils::enableTcpKeepAlives;
using netdutils::isOk;
using netdutils::Slice;
using netdutils::Status;

namespace net {
namespace {

constexpr const char kCaCertDir[] = "/system/etc/security/cacerts";
constexpr size_t SHA256_SIZE = SHA256_DIGEST_LENGTH;

int waitForReading(int fd) {
    struct pollfd fds = { .fd = fd, .events = POLLIN };
    const int ret = TEMP_FAILURE_RETRY(poll(&fds, 1, -1));
    return ret;
}

int waitForWriting(int fd) {
    struct pollfd fds = { .fd = fd, .events = POLLOUT };
    const int ret = TEMP_FAILURE_RETRY(poll(&fds, 1, -1));
    return ret;
}

std::string markToFwmarkString(unsigned mMark) {
    Fwmark mark;
    mark.intValue = mMark;
    return android::base::StringPrintf("%d, %d, %d, %d, %d", mark.netId, mark.explicitlySelected,
                                       mark.protectedFromVpn, mark.permission, mark.uidBillingDone);
}

}  // namespace

Status DnsTlsSocket::tcpConnect() {
    LOG(DEBUG) << mMark << " connecting TCP socket";
    int type = SOCK_NONBLOCK | SOCK_CLOEXEC;
    switch (mServer.protocol) {
        case IPPROTO_TCP:
            type |= SOCK_STREAM;
            break;
        default:
            return Status(EPROTONOSUPPORT);
    }

    mSslFd.reset(socket(mServer.ss.ss_family, type, mServer.protocol));
    if (mSslFd.get() == -1) {
        LOG(ERROR) << "Failed to create socket";
        return Status(errno);
    }

    if (fchown(mSslFd.get(), AID_DNS, -1) == -1) {
        LOG(WARNING) << "Failed to chown socket: %s" << strerror(errno);
    }

    const socklen_t len = sizeof(mMark);
    if (setsockopt(mSslFd.get(), SOL_SOCKET, SO_MARK, &mMark, len) == -1) {
        LOG(ERROR) << "Failed to set socket mark";
        mSslFd.reset();
        return Status(errno);
    }

    const Status tfo = enableSockopt(mSslFd.get(), SOL_TCP, TCP_FASTOPEN_CONNECT);
    if (!isOk(tfo) && tfo.code() != ENOPROTOOPT) {
        LOG(WARNING) << "Failed to enable TFO: " << tfo.msg();
    }

    // Send 5 keepalives, 3 seconds apart, after 15 seconds of inactivity.
    enableTcpKeepAlives(mSslFd.get(), 15U, 5U, 3U).ignoreError();

    if (connect(mSslFd.get(), reinterpret_cast<const struct sockaddr *>(&mServer.ss),
                sizeof(mServer.ss)) != 0 &&
            errno != EINPROGRESS) {
        LOG(DEBUG) << "Socket failed to connect";
        mSslFd.reset();
        return Status(errno);
    }

    return netdutils::status::ok;
}

bool getSPKIDigest(const X509* cert, std::vector<uint8_t>* out) {
    int spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), nullptr);
    unsigned char spki[spki_len];
    unsigned char* temp = spki;
    if (spki_len != i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &temp)) {
        LOG(WARNING) << "SPKI length mismatch";
        return false;
    }
    out->resize(SHA256_SIZE);
    unsigned int digest_len = 0;
    int ret = EVP_Digest(spki, spki_len, out->data(), &digest_len, EVP_sha256(), nullptr);
    if (ret != 1) {
        LOG(WARNING) << "Server cert digest extraction failed";
        return false;
    }
    if (digest_len != out->size()) {
        LOG(WARNING) << "Wrong digest length: " << digest_len;
        return false;
    }
    return true;
}

bool DnsTlsSocket::initialize() {
    // This method should only be called once, at the beginning, so locking should be
    // unnecessary.  This lock only serves to help catch bugs in code that calls this method.
    std::lock_guard guard(mLock);
    if (mSslCtx) {
        // This is a bug in the caller.
        return false;
    }
    mSslCtx.reset(SSL_CTX_new(TLS_method()));
    if (!mSslCtx) {
        return false;
    }

    // Load system CA certs for hostname verification.
    //
    // For discussion of alternative, sustainable approaches see b/71909242.
    if (SSL_CTX_load_verify_locations(mSslCtx.get(), nullptr, kCaCertDir) != 1) {
        LOG(ERROR) << "Failed to load CA cert dir: " << kCaCertDir;
        return false;
    }

    // Enable TLS false start
    SSL_CTX_set_false_start_allowed_without_alpn(mSslCtx.get(), 1);
    SSL_CTX_set_mode(mSslCtx.get(), SSL_MODE_ENABLE_FALSE_START);

    // Enable session cache
    mCache->prepareSslContext(mSslCtx.get());

    // Connect
    Status status = tcpConnect();
    if (!status.ok()) {
        return false;
    }
    mSsl = sslConnect(mSslFd.get());
    if (!mSsl) {
        return false;
    }

    mEventFd.reset(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));

    // Start the I/O loop.
    mLoopThread.reset(new std::thread(&DnsTlsSocket::loop, this));

    return true;
}

bssl::UniquePtr<SSL> DnsTlsSocket::sslConnect(int fd) {
    if (!mSslCtx) {
        LOG(ERROR) << "Internal error: context is null in sslConnect";
        return nullptr;
    }
    if (!SSL_CTX_set_min_proto_version(mSslCtx.get(), TLS1_2_VERSION)) {
        LOG(ERROR) << "Failed to set minimum TLS version";
        return nullptr;
    }

    bssl::UniquePtr<SSL> ssl(SSL_new(mSslCtx.get()));
    // This file descriptor is owned by mSslFd, so don't let libssl close it.
    bssl::UniquePtr<BIO> bio(BIO_new_socket(fd, BIO_NOCLOSE));
    SSL_set_bio(ssl.get(), bio.get(), bio.get());
    bio.release();

    if (!mCache->prepareSsl(ssl.get())) {
        return nullptr;
    }

    if (!mServer.name.empty()) {
        if (SSL_set_tlsext_host_name(ssl.get(), mServer.name.c_str()) != 1) {
            LOG(ERROR) << "ailed to set SNI to " << mServer.name;
            return nullptr;
        }
        X509_VERIFY_PARAM* param = SSL_get0_param(ssl.get());
        if (X509_VERIFY_PARAM_set1_host(param, mServer.name.data(), mServer.name.size()) != 1) {
            LOG(ERROR) << "Failed to set verify host param to " << mServer.name;
            return nullptr;
        }
        // This will cause the handshake to fail if certificate verification fails.
        SSL_set_verify(ssl.get(), SSL_VERIFY_PEER, nullptr);
    }

    bssl::UniquePtr<SSL_SESSION> session = mCache->getSession();
    if (session) {
        LOG(DEBUG) << "Setting session";
        SSL_set_session(ssl.get(), session.get());
    } else {
        LOG(DEBUG) << "No session available";
    }

    for (;;) {
        LOG(DEBUG) << " Calling SSL_connect with " << markToFwmarkString(mMark);
        int ret = SSL_connect(ssl.get());
        LOG(DEBUG) << " SSL_connect returned " << ret << " with " << markToFwmarkString(mMark);
        if (ret == 1) break;  // SSL handshake complete;

        const int ssl_err = SSL_get_error(ssl.get(), ret);
        switch (ssl_err) {
            case SSL_ERROR_WANT_READ:
                if (waitForReading(fd) != 1) {
                    PLOG(WARNING) << "SSL_connect read error, " << markToFwmarkString(mMark);
                    return nullptr;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if (waitForWriting(fd) != 1) {
                    PLOG(WARNING) << "SSL_connect write error, " << markToFwmarkString(mMark);
                    return nullptr;
                }
                break;
            default:
                PLOG(WARNING) << "SSL_connect ssl error =" << ssl_err << ", "
                              << markToFwmarkString(mMark);
                return nullptr;
        }
    }

    // TODO: Call SSL_shutdown before discarding the session if validation fails.
    if (!mServer.fingerprints.empty()) {
        LOG(DEBUG) << "Checking DNS over TLS fingerprint";

        // We only care that the chain is internally self-consistent, not that
        // it chains to a trusted root, so we can ignore some kinds of errors.
        // TODO: Add a CA root verification mode that respects these errors.
        int verify_result = SSL_get_verify_result(ssl.get());
        switch (verify_result) {
            case X509_V_OK:
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            case X509_V_ERR_CERT_UNTRUSTED:
                break;
            default:
                LOG(WARNING) << "Invalid certificate chain, error " << verify_result;
                return nullptr;
        }

        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl.get());
        if (!chain) {
            LOG(WARNING) << "Server has null certificate";
            return nullptr;
        }
        // Chain and its contents are owned by ssl, so we don't need to free explicitly.
        bool matched = false;
        for (size_t i = 0; i < sk_X509_num(chain); ++i) {
            // This appears to be O(N^2), but there doesn't seem to be a straightforward
            // way to walk a STACK_OF nondestructively in linear time.
            X509* cert = sk_X509_value(chain, i);
            std::vector<uint8_t> digest;
            if (!getSPKIDigest(cert, &digest)) {
                LOG(ERROR) << "Digest computation failed";
                return nullptr;
            }

            if (mServer.fingerprints.count(digest) > 0) {
                matched = true;
                break;
            }
        }

        if (!matched) {
            LOG(WARNING) << "No matching fingerprint";
            return nullptr;
        }

        LOG(DEBUG) << "DNS over TLS fingerprint is correct";
    }

    LOG(DEBUG) << mMark << " handshake complete";

    return ssl;
}

void DnsTlsSocket::sslDisconnect() {
    if (mSsl) {
        SSL_shutdown(mSsl.get());
        mSsl.reset();
    }
    mSslFd.reset();
}

bool DnsTlsSocket::sslWrite(const Slice buffer) {
    LOG(DEBUG) << mMark << " Writing " << buffer.size() << " bytes";
    for (;;) {
        int ret = SSL_write(mSsl.get(), buffer.base(), buffer.size());
        if (ret == int(buffer.size())) break;  // SSL write complete;

        if (ret < 1) {
            const int ssl_err = SSL_get_error(mSsl.get(), ret);
            switch (ssl_err) {
                case SSL_ERROR_WANT_WRITE:
                    if (waitForWriting(mSslFd.get()) != 1) {
                        LOG(DEBUG) << "SSL_write error";
                        return false;
                    }
                    continue;
                case 0:
                    break;  // SSL write complete;
                default:
                    LOG(DEBUG) << "SSL_write error " << ssl_err;
                    return false;
            }
        }
    }
    LOG(DEBUG) << mMark << " Wrote " << buffer.size() << " bytes";
    return true;
}

void DnsTlsSocket::loop() {
    std::lock_guard guard(mLock);
    std::deque<std::vector<uint8_t>> q;

    const int timeout_msecs = DnsTlsSocket::kIdleTimeout.count() * 1000;
    while (true) {
        // poll() ignores negative fds
        struct pollfd fds[2] = { { .fd = -1 }, { .fd = -1 } };
        enum { SSLFD = 0, EVENTFD = 1 };

        // Always listen for a response from server.
        fds[SSLFD].fd = mSslFd.get();
        fds[SSLFD].events = POLLIN;

        // If we have pending queries, wait for space to write one.
        // Otherwise, listen for new queries.
        // Note: This blocks the destructor until q is empty, i.e. until all pending
        // queries are sent or have failed to send.
        if (!q.empty()) {
            fds[SSLFD].events |= POLLOUT;
        } else {
            fds[EVENTFD].fd = mEventFd.get();
            fds[EVENTFD].events = POLLIN;
        }

        const int s = TEMP_FAILURE_RETRY(poll(fds, std::size(fds), timeout_msecs));
        if (s == 0) {
            LOG(DEBUG) << "Idle timeout";
            break;
        }
        if (s < 0) {
            LOG(DEBUG) << "Poll failed: " << errno;
            break;
        }
        if (fds[SSLFD].revents & (POLLIN | POLLERR | POLLHUP)) {
            if (!readResponse()) {
                LOG(DEBUG) << "SSL remote close or read error.";
                break;
            }
        }
        if (fds[EVENTFD].revents & (POLLIN | POLLERR)) {
            int64_t num_queries;
            ssize_t res = read(mEventFd.get(), &num_queries, sizeof(num_queries));
            if (res < 0) {
                LOG(WARNING) << "Error during eventfd read";
                break;
            } else if (res == 0) {
                LOG(WARNING) << "eventfd closed; disconnecting";
                break;
            } else if (res != sizeof(num_queries)) {
                LOG(ERROR) << "Int size mismatch: " << res << " != " << sizeof(num_queries);
                break;
            } else if (num_queries < 0) {
                LOG(DEBUG) << "Negative eventfd read indicates destructor-initiated shutdown";
                break;
            }
            // Take ownership of all pending queries.  (q is always empty here.)
            mQueue.swap(q);
        } else if (fds[SSLFD].revents & POLLOUT) {
            // q cannot be empty here.
            // Sending the entire queue here would risk a TCP flow control deadlock, so
            // we only send a single query on each cycle of this loop.
            // TODO: Coalesce multiple pending queries if there is enough space in the
            // write buffer.
            if (!sendQuery(q.front())) {
                break;
            }
            q.pop_front();
        }
    }
    LOG(DEBUG) << "Disconnecting";
    sslDisconnect();
    LOG(DEBUG) << "Calling onClosed";
    mObserver->onClosed();
    LOG(DEBUG) << "Ending loop";
}

DnsTlsSocket::~DnsTlsSocket() {
    LOG(DEBUG) << "Destructor";
    // This will trigger an orderly shutdown in loop().
    requestLoopShutdown();
    {
        // Wait for the orderly shutdown to complete.
        std::lock_guard guard(mLock);
        if (mLoopThread && std::this_thread::get_id() == mLoopThread->get_id()) {
            LOG(ERROR) << "Violation of re-entrance precondition";
            return;
        }
    }
    if (mLoopThread) {
        LOG(DEBUG) << "Waiting for loop thread to terminate";
        mLoopThread->join();
        mLoopThread.reset();
    }
    LOG(DEBUG) << "Destructor completed";
}

bool DnsTlsSocket::query(uint16_t id, const Slice query) {
    // Compose the entire message in a single buffer, so that it can be
    // sent as a single TLS record.
    std::vector<uint8_t> buf(query.size() + 4);
    // Write 2-byte length
    uint16_t len = query.size() + 2;  // + 2 for the ID.
    buf[0] = len >> 8;
    buf[1] = len;
    // Write 2-byte ID
    buf[2] = id >> 8;
    buf[3] = id;
    // Copy body
    std::memcpy(buf.data() + 4, query.base(), query.size());

    mQueue.push(std::move(buf));
    // Increment the mEventFd counter by 1.
    return incrementEventFd(1);
}

void DnsTlsSocket::requestLoopShutdown() {
    if (mEventFd != -1) {
        // Write a negative number to the eventfd.  This triggers an immediate shutdown.
        incrementEventFd(INT64_MIN);
    }
}

bool DnsTlsSocket::incrementEventFd(const int64_t count) {
    if (mEventFd == -1) {
        LOG(ERROR) << "eventfd is not initialized";
        return false;
    }
    ssize_t written = write(mEventFd.get(), &count, sizeof(count));
    if (written != sizeof(count)) {
        LOG(ERROR) << "Failed to increment eventfd by " << count;
        return false;
    }
    return true;
}

// Read exactly len bytes into buffer or fail with an SSL error code
int DnsTlsSocket::sslRead(const Slice buffer, bool wait) {
    size_t remaining = buffer.size();
    while (remaining > 0) {
        int ret = SSL_read(mSsl.get(), buffer.limit() - remaining, remaining);
        if (ret == 0) {
            if (remaining < buffer.size())
                LOG(WARNING) << "SSL closed with " << remaining << " of " << buffer.size()
                             << " bytes remaining";
            return SSL_ERROR_ZERO_RETURN;
        }

        if (ret < 0) {
            const int ssl_err = SSL_get_error(mSsl.get(), ret);
            if (wait && ssl_err == SSL_ERROR_WANT_READ) {
                if (waitForReading(mSslFd.get()) != 1) {
                    LOG(DEBUG) << "Poll failed in sslRead: " << errno;
                    return SSL_ERROR_SYSCALL;
                }
                continue;
            } else {
                LOG(DEBUG) << "SSL_read error " << ssl_err;
                return ssl_err;
            }
        }

        remaining -= ret;
        wait = true;  // Once a read is started, try to finish.
    }
    return SSL_ERROR_NONE;
}

bool DnsTlsSocket::sendQuery(const std::vector<uint8_t>& buf) {
    if (!sslWrite(netdutils::makeSlice(buf))) {
        return false;
    }
    LOG(DEBUG) << mMark << " SSL_write complete";
    return true;
}

bool DnsTlsSocket::readResponse() {
    LOG(DEBUG) << "reading response";
    uint8_t responseHeader[2];
    int err = sslRead(Slice(responseHeader, 2), false);
    if (err == SSL_ERROR_WANT_READ) {
        LOG(DEBUG) << "Ignoring spurious wakeup from server";
        return true;
    }
    if (err != SSL_ERROR_NONE) {
        return false;
    }
    // Truncate responses larger than MAX_SIZE.  This is safe because a DNS packet is
    // always invalid when truncated, so the response will be treated as an error.
    constexpr uint16_t MAX_SIZE = 8192;
    const uint16_t responseSize = (responseHeader[0] << 8) | responseHeader[1];
    LOG(DEBUG) << mMark << " Expecting response of size " << responseSize;
    std::vector<uint8_t> response(std::min(responseSize, MAX_SIZE));
    if (sslRead(netdutils::makeSlice(response), true) != SSL_ERROR_NONE) {
        LOG(DEBUG) << mMark << " Failed to read " << response.size() << " bytes";
        return false;
    }
    uint16_t remainingBytes = responseSize - response.size();
    while (remainingBytes > 0) {
        constexpr uint16_t CHUNK_SIZE = 2048;
        std::vector<uint8_t> discard(std::min(remainingBytes, CHUNK_SIZE));
        if (sslRead(netdutils::makeSlice(discard), true) != SSL_ERROR_NONE) {
            LOG(DEBUG) << mMark << " Failed to discard " << discard.size() << " bytes";
            return false;
        }
        remainingBytes -= discard.size();
    }
    LOG(DEBUG) << mMark << " SSL_read complete";

    mObserver->onResponse(std::move(response));
    return true;
}

}  // end of namespace net
}  // end of namespace android
