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

#include "dns/DnsTlsTransport.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <openssl/err.h>

#define LOG_TAG "DnsTlsTransport"
#define DBG 0

#include "log/log.h"
#include "Fwmark.h"
#undef ADD  // already defined in nameser.h
#include "NetdConstants.h"
#include "Permission.h"


namespace android {
namespace net {

namespace {

bool setNonBlocking(int fd, bool enabled) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return false;

    if (enabled) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    return (fcntl(fd, F_SETFL, flags) == 0);
}

int waitForReading(int fd) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    const int ret = TEMP_FAILURE_RETRY(select(fd + 1, &fds, nullptr, nullptr, nullptr));
    if (DBG && ret <= 0) {
        ALOGD("select");
    }
    return ret;
}

int waitForWriting(int fd) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    const int ret = TEMP_FAILURE_RETRY(select(fd + 1, nullptr, &fds, nullptr, nullptr));
    if (DBG && ret <= 0) {
        ALOGD("select");
    }
    return ret;
}

}  // namespace

android::base::unique_fd DnsTlsTransport::makeConnectedSocket() const {
    if (DBG) {
        ALOGD("%u connecting TCP socket", mMark);
    }
    android::base::unique_fd fd;
    int type = SOCK_NONBLOCK | SOCK_CLOEXEC;
    switch (mServer.protocol) {
        case IPPROTO_TCP:
            type |= SOCK_STREAM;
            break;
        default:
            errno = EPROTONOSUPPORT;
            return fd;
    }

    fd.reset(socket(mServer.ss.ss_family, type, mServer.protocol));
    if (fd.get() == -1) {
        return fd;
    }

    const socklen_t len = sizeof(mMark);
    if (setsockopt(fd.get(), SOL_SOCKET, SO_MARK, &mMark, len) == -1) {
        fd.reset();
    } else if (connect(fd.get(),
            reinterpret_cast<const struct sockaddr *>(&mServer.ss), sizeof(mServer.ss)) != 0
        && errno != EINPROGRESS) {
        fd.reset();
    }

    if (!setNonBlocking(fd, false)) {
        ALOGE("Failed to disable nonblocking status on DNS-over-TLS fd");
        fd.reset();
    }

    return fd;
}

bool getSPKIDigest(const X509* cert, std::vector<uint8_t>* out) {
    int spki_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
    unsigned char spki[spki_len];
    unsigned char* temp = spki;
    if (spki_len != i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &temp)) {
        ALOGW("SPKI length mismatch");
        return false;
    }
    out->resize(SHA256_SIZE);
    unsigned int digest_len = 0;
    int ret = EVP_Digest(spki, spki_len, out->data(), &digest_len, EVP_sha256(), NULL);
    if (ret != 1) {
        ALOGW("Server cert digest extraction failed");
        return false;
    }
    if (digest_len != out->size()) {
        ALOGW("Wrong digest length: %d", digest_len);
        return false;
    }
    return true;
}

bool DnsTlsTransport::initialize() {
    // This method should only be called once, at the beginning, so locking should be
    // unnecessary.  This lock only serves to help catch bugs in code that calls this method.
    std::lock_guard<std::mutex> guard(mLock);
    if (mSslCtx) {
        // This is a bug in the caller.
        return false;
    }
    mSslCtx.reset(SSL_CTX_new(TLS_method()));
    if (!mSslCtx) {
        return false;
    }
    SSL_CTX_sess_set_new_cb(mSslCtx.get(), DnsTlsTransport::newSessionCallback);
    SSL_CTX_sess_set_remove_cb(mSslCtx.get(), DnsTlsTransport::removeSessionCallback);
    return true;
}

bssl::UniquePtr<SSL> DnsTlsTransport::sslConnect(int fd) {
    // Check TLS context.
    if (!mSslCtx) {
        ALOGE("Internal error: context is null in ssl connect");
        return nullptr;
    }
    if (!SSL_CTX_set_max_proto_version(mSslCtx.get(), TLS1_3_VERSION) ||
        !SSL_CTX_set_min_proto_version(mSslCtx.get(), TLS1_2_VERSION)) {
        ALOGE("failed to min/max TLS versions");
        return nullptr;
    }

    bssl::UniquePtr<SSL> ssl(SSL_new(mSslCtx.get()));
    // This file descriptor is owned by a unique_fd, so don't let libssl close it.
    bssl::UniquePtr<BIO> bio(BIO_new_socket(fd, BIO_NOCLOSE));
    SSL_set_bio(ssl.get(), bio.get(), bio.get());
    bio.release();

    // Add this transport as the 0-index extra data for the socket.
    // This is used by newSessionCallback.
    if (SSL_set_ex_data(ssl.get(), 0, this) != 1) {
        ALOGE("failed to associate SSL socket to transport");
        return nullptr;
    }

    // Add this transport as the 0-index extra data for the context.
    // This is used by removeSessionCallback.
    if (SSL_CTX_set_ex_data(mSslCtx.get(), 0, this) != 1) {
        ALOGE("failed to associate SSL context to transport");
        return nullptr;
    }

    if (!mServer.name.empty()) {
        if (SSL_set_tlsext_host_name(ssl.get(), mServer.name.c_str()) != 1) {
            ALOGE("Failed to set SNI to %s", mServer.name.c_str());
            return nullptr;
        }
        X509_VERIFY_PARAM* param = SSL_get0_param(ssl.get());
        X509_VERIFY_PARAM_set1_host(param, mServer.name.c_str(), 0);
        // This will cause the handshake to fail if certificate verification fails.
        SSL_set_verify(ssl.get(), SSL_VERIFY_PEER, nullptr);
    }

    bssl::UniquePtr<SSL_SESSION> session;
    {
        std::lock_guard<std::mutex> guard(mLock);
        if (!mSessions.empty()) {
            session = std::move(mSessions.front());
            mSessions.pop_front();
        } else if (DBG) {
            ALOGD("Starting without session ticket.");
        }
    }
    if (session) {
        SSL_set_session(ssl.get(), session.get());
    }

    for (;;) {
        if (DBG) {
            ALOGD("%u Calling SSL_connect", mMark);
        }
        int ret = SSL_connect(ssl.get());
        if (DBG) {
            ALOGD("%u SSL_connect returned %d", mMark, ret);
        }
        if (ret == 1) break;  // SSL handshake complete;

        const int ssl_err = SSL_get_error(ssl.get(), ret);
        switch (ssl_err) {
            case SSL_ERROR_WANT_READ:
                if (waitForReading(fd) != 1) {
                    ALOGW("SSL_connect read error");
                    return nullptr;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if (waitForWriting(fd) != 1) {
                    ALOGW("SSL_connect write error");
                    return nullptr;
                }
                break;
            default:
                ALOGW("SSL_connect error %d, errno=%d", ssl_err, errno);
                return nullptr;
        }
    }

    if (!mServer.fingerprints.empty()) {
        if (DBG) {
            ALOGD("Checking DNS over TLS fingerprint");
        }

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
                ALOGW("Invalid certificate chain, error %d", verify_result);
                return nullptr;
        }

        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl.get());
        if (!chain) {
            ALOGW("Server has null certificate");
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
                ALOGE("Digest computation failed");
                return nullptr;
            }

            if (mServer.fingerprints.count(digest) > 0) {
                matched = true;
                break;
            }
        }

        if (!matched) {
            ALOGW("No matching fingerprint");
            return nullptr;
        }

        if (DBG) {
            ALOGD("DNS over TLS fingerprint is correct");
        }
    }

    if (DBG) {
        ALOGD("%u handshake complete", mMark);
    }

    return ssl;
}

// static
int DnsTlsTransport::newSessionCallback(SSL* ssl, SSL_SESSION* session) {
    if (!session) {
        return 0;
    }
    if (DBG) {
        ALOGD("Recording session ticket");
    }
    DnsTlsTransport* xport = reinterpret_cast<DnsTlsTransport*>(
            SSL_get_ex_data(ssl, 0));
    if (!xport) {
        ALOGE("null transport in new session callback");
        return 0;
    }
    xport->recordSession(session);
    return 1;
}

void DnsTlsTransport::removeSessionCallback(SSL_CTX* ssl_ctx, SSL_SESSION* session) {
    if (DBG) {
        ALOGD("Removing session ticket");
    }
    DnsTlsTransport* xport = reinterpret_cast<DnsTlsTransport*>(
            SSL_CTX_get_ex_data(ssl_ctx, 0));
    if (!xport) {
        ALOGE("null transport in remove session callback");
        return;
    }
    xport->removeSession(session);
}

void DnsTlsTransport::recordSession(SSL_SESSION* session) {
    std::lock_guard<std::mutex> guard(mLock);
    mSessions.emplace_front(session);
    if (mSessions.size() > 5) {
        if (DBG) {
            ALOGD("Too many sessions; trimming");
        }
        mSessions.pop_back();
    }
}

void DnsTlsTransport::removeSession(SSL_SESSION* session) {
    std::lock_guard<std::mutex> guard(mLock);
    if (session) {
        // TODO: Consider implementing targeted removal.
        mSessions.clear();
    }
}

void DnsTlsTransport::sslDisconnect(bssl::UniquePtr<SSL> ssl, base::unique_fd fd) {
    if (ssl) {
        SSL_shutdown(ssl.get());
        ssl.reset();
    }
    fd.reset();
}

bool DnsTlsTransport::sslWrite(int fd, SSL *ssl, const uint8_t *buffer, int len) {
    if (DBG) {
        ALOGD("%u Writing %d bytes", mMark, len);
    }
    for (;;) {
        int ret = SSL_write(ssl, buffer, len);
        if (ret == len) break;  // SSL write complete;

        if (ret < 1) {
            const int ssl_err = SSL_get_error(ssl, ret);
            switch (ssl_err) {
                case SSL_ERROR_WANT_WRITE:
                    if (waitForWriting(fd) != 1) {
                        if (DBG) {
                            ALOGW("SSL_write error");
                        }
                        return false;
                    }
                    continue;
                case 0:
                    break;  // SSL write complete;
                default:
                    if (DBG) {
                        ALOGW("SSL_write error %d", ssl_err);
                    }
                    return false;
            }
        }
    }
    if (DBG) {
        ALOGD("%u Wrote %d bytes", mMark, len);
    }
    return true;
}

// Read exactly len bytes into buffer or fail
bool DnsTlsTransport::sslRead(int fd, SSL *ssl, uint8_t *buffer, int len) {
    int remaining = len;
    while (remaining > 0) {
        int ret = SSL_read(ssl, buffer + (len - remaining), remaining);
        if (ret == 0) {
            ALOGE("SSL socket closed with %i of %i bytes remaining", remaining, len);
            return false;
        }

        if (ret < 0) {
            const int ssl_err = SSL_get_error(ssl, ret);
            if (ssl_err == SSL_ERROR_WANT_READ) {
                if (waitForReading(fd) != 1) {
                    if (DBG) {
                        ALOGW("SSL_read error");
                    }
                    return false;
                }
                continue;
            } else {
                if (DBG) {
                    ALOGW("SSL_read error %d", ssl_err);
                }
                return false;
            }
        }

        remaining -= ret;
    }
    return true;
}

DnsTlsTransport::Response DnsTlsTransport::query(const uint8_t *query, size_t qlen,
        uint8_t *response, size_t limit, int *resplen) {
    android::base::unique_fd fd = makeConnectedSocket();
    if (fd.get() < 0) {
        ALOGD("%u makeConnectedSocket() failed with: %s", mMark, strerror(errno));
        return Response::network_error;
    }
    bssl::UniquePtr<SSL> ssl = sslConnect(fd.get());
    if (!ssl) {
        return Response::network_error;
    }

    Response res = sendQuery(fd.get(), ssl.get(), query, qlen);
    if (res == Response::success) {
        res = readResponse(fd.get(), ssl.get(), query, response, limit, resplen);
    }

    sslDisconnect(std::move(ssl), std::move(fd));
    return res;
}

DnsTlsTransport::Response DnsTlsTransport::sendQuery(int fd, SSL* ssl,
        const uint8_t *query, size_t qlen) {
    if (DBG) {
        ALOGD("sending query");
    }
    uint8_t queryHeader[2];
    queryHeader[0] = qlen >> 8;
    queryHeader[1] = qlen;
    if (!sslWrite(fd, ssl, queryHeader, 2)) {
        return Response::network_error;
    }
    if (!sslWrite(fd, ssl, query, qlen)) {
        return Response::network_error;
    }
    if (DBG) {
        ALOGD("%u SSL_write complete", mMark);
    }
    return Response::success;
}

DnsTlsTransport::Response DnsTlsTransport::readResponse(int fd, SSL* ssl,
        const uint8_t *query, uint8_t *response, size_t limit, int *resplen) {
    if (DBG) {
        ALOGD("reading response");
    }
    uint8_t responseHeader[2];
    if (!sslRead(fd, ssl, responseHeader, 2)) {
        if (DBG) {
            ALOGW("%u Failed to read 2-byte length header", mMark);
        }
        return Response::network_error;
    }
    const uint16_t responseSize = (responseHeader[0] << 8) | responseHeader[1];
    if (DBG) {
        ALOGD("%u Expecting response of size %i", mMark, responseSize);
    }
    if (responseSize > limit) {
        ALOGE("%u Response doesn't fit in output buffer: %i", mMark, responseSize);
        return Response::limit_error;
    }
    if (!sslRead(fd, ssl, response, responseSize)) {
        if (DBG) {
            ALOGW("%u Failed to read %i bytes", mMark, responseSize);
        }
        return Response::network_error;
    }
    if (DBG) {
        ALOGD("%u SSL_read complete", mMark);
    }

    if (response[0] != query[0] || response[1] != query[1]) {
        ALOGE("reply query ID != query ID");
        return Response::internal_error;
    }

    *resplen = responseSize;
    return Response::success;
}

// static
bool DnsTlsTransport::validate(const DnsTlsServer& server, unsigned netid) {
    if (DBG) {
        ALOGD("Beginning validation on %u", netid);
    }
    // Generate "<random>-dnsotls-ds.metric.gstatic.com", which we will lookup through |ss| in
    // order to prove that it is actually a working DNS over TLS server.
    static const char kDnsSafeChars[] =
            "abcdefhijklmnopqrstuvwxyz"
            "ABCDEFHIJKLMNOPQRSTUVWXYZ"
            "0123456789";
    const auto c = [](uint8_t rnd) -> uint8_t {
        return kDnsSafeChars[(rnd % ARRAY_SIZE(kDnsSafeChars))];
    };
    uint8_t rnd[8];
    arc4random_buf(rnd, ARRAY_SIZE(rnd));
    // We could try to use res_mkquery() here, but it's basically the same.
    uint8_t query[] = {
        rnd[6], rnd[7],  // [0-1]   query ID
        1, 0,  // [2-3]   flags; query[2] = 1 for recursion desired (RD).
        0, 1,  // [4-5]   QDCOUNT (number of queries)
        0, 0,  // [6-7]   ANCOUNT (number of answers)
        0, 0,  // [8-9]   NSCOUNT (number of name server records)
        0, 0,  // [10-11] ARCOUNT (number of additional records)
        17, c(rnd[0]), c(rnd[1]), c(rnd[2]), c(rnd[3]), c(rnd[4]), c(rnd[5]),
            '-', 'd', 'n', 's', 'o', 't', 'l', 's', '-', 'd', 's',
        6, 'm', 'e', 't', 'r', 'i', 'c',
        7, 'g', 's', 't', 'a', 't', 'i', 'c',
        3, 'c', 'o', 'm',
        0,  // null terminator of FQDN (root TLD)
        0, ns_t_aaaa,  // QTYPE
        0, ns_c_in     // QCLASS
    };
    const int qlen = ARRAY_SIZE(query);

    const int kRecvBufSize = 4 * 1024;
    uint8_t recvbuf[kRecvBufSize];

    // At validation time, we only know the netId, so we have to guess/compute the
    // corresponding socket mark.
    Fwmark fwmark;
    fwmark.permission = PERMISSION_SYSTEM;
    fwmark.explicitlySelected = true;
    fwmark.protectedFromVpn = true;
    fwmark.netId = netid;
    unsigned mark = fwmark.intValue;
    int replylen = 0;
    DnsTlsTransport transport(server, mark);
    if (!transport.initialize()) {
        return false;
    }
    transport.query(query, qlen, recvbuf, kRecvBufSize, &replylen);
    if (replylen == 0) {
        if (DBG) {
            ALOGD("query failed");
        }
        return false;
    }

    if (replylen < NS_HFIXEDSZ) {
        if (DBG) {
            ALOGW("short response: %d", replylen);
        }
        return false;
    }

    const int qdcount = (recvbuf[4] << 8) | recvbuf[5];
    if (qdcount != 1) {
        ALOGW("reply query count != 1: %d", qdcount);
        return false;
    }

    const int ancount = (recvbuf[6] << 8) | recvbuf[7];
    if (DBG) {
        ALOGD("%u answer count: %d", netid, ancount);
    }

    // TODO: Further validate the response contents (check for valid AAAA record, ...).
    // Note that currently, integration tests rely on this function accepting a
    // response with zero records.
#if 0
    for (int i = 0; i < resplen; i++) {
        ALOGD("recvbuf[%d] = %d %c", i, recvbuf[i], recvbuf[i]);
    }
#endif
    return true;
}

}  // namespace net
}  // namespace android
