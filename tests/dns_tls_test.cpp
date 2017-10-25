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

#define LOG_TAG "dns_tls_test"

#include <gtest/gtest.h>

#include "dns/DnsTlsDispatcher.h"
#include "dns/DnsTlsServer.h"
#include "dns/DnsTlsSessionCache.h"
#include "dns/DnsTlsSocket.h"
#include "dns/DnsTlsTransport.h"
#include "dns/IDnsTlsSocket.h"
#include "dns/IDnsTlsSocketFactory.h"

#include <chrono>
#include <arpa/inet.h>
#include <android-base/macros.h>
#include <netdutils/Slice.h>

#include "log/log.h"

namespace android {
namespace net {

using netdutils::Slice;
using netdutils::makeSlice;

typedef std::vector<uint8_t> bytevec;

static void parseServer(const char* server, in_port_t port, sockaddr_storage* parsed) {
    sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(parsed);
    if (inet_pton(AF_INET, server, &(sin->sin_addr)) == 1) {
        // IPv4 parse succeeded, so it's IPv4
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        return;
    }
    sockaddr_in6* sin6 = reinterpret_cast<sockaddr_in6*>(parsed);
    if (inet_pton(AF_INET6, server, &(sin6->sin6_addr)) == 1){
        // IPv6 parse succeeded, so it's IPv6.
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        return;
    }
    ALOGE("Failed to parse server address: %s", server);
}

bytevec FINGERPRINT1 = { 1 };

std::string SERVERNAME1 = "dns.example.com";

// BaseTest just provides constants that are useful for the tests.
class BaseTest : public ::testing::Test {
protected:
    BaseTest() {
        parseServer("192.0.2.1", 853, &V4ADDR1);
        parseServer("192.0.2.2", 853, &V4ADDR2);

        SERVER1 = DnsTlsServer(V4ADDR1);
        SERVER1.fingerprints.insert(FINGERPRINT1);
        SERVER1.name = SERVERNAME1;
    }

    sockaddr_storage V4ADDR1;
    sockaddr_storage V4ADDR2;

    DnsTlsServer SERVER1;
};

bytevec make_query(uint16_t id, size_t size) {
    bytevec vec(size);
    vec[0] = id >> 8;
    vec[1] = id;
    // Arbitrarily fill the query body with unique data.
    for (size_t i = 2; i < size; ++i) {
        vec[i] = id + i;
    }
    return vec;
}

// Query constants
const unsigned MARK = 123;
const uint16_t ID = 52;
const uint16_t SIZE = 22;
const bytevec QUERY = make_query(ID, SIZE);

template <class T>
class FakeSocketFactory : public IDnsTlsSocketFactory {
public:
    FakeSocketFactory() {}
    std::unique_ptr<IDnsTlsSocket> createDnsTlsSocket(
            const DnsTlsServer& server ATTRIBUTE_UNUSED,
            unsigned mark ATTRIBUTE_UNUSED,
            DnsTlsSessionCache* cache ATTRIBUTE_UNUSED) override {
        return std::make_unique<T>();
    }
};

bytevec make_echo(uint16_t id, const Slice query) {
    bytevec response(query.size() + 2);
    response[0] = id >> 8;
    response[1] = id;
    // Echo the query as the fake response.
    memcpy(response.data() + 2, query.base(), query.size());
    return response;
}

// Simplest possible fake server.  This just echoes the query as the response.
class FakeSocketEcho : public IDnsTlsSocket {
public:
    FakeSocketEcho() {}
    DnsTlsServer::Result query(uint16_t id, const Slice query) override {
        // Return the response immediately.
        return { .code = DnsTlsServer::Response::success, .response = make_echo(id, query) };
    }
};

class TransportTest : public BaseTest {};

TEST_F(TransportTest, Query) {
    FakeSocketFactory<FakeSocketEcho> factory;
    DnsTlsTransport transport(SERVER1, MARK, &factory);
    auto r = transport.query(makeSlice(QUERY));

    EXPECT_EQ(DnsTlsTransport::Response::success, r.code);
    EXPECT_EQ(QUERY, r.response);
}

TEST_F(TransportTest, SerialQueries) {
    FakeSocketFactory<FakeSocketEcho> factory;
    DnsTlsTransport transport(SERVER1, MARK, &factory);
    // Send more than 65536 queries serially.
    for (int i = 0; i < 100000; ++i) {
        auto r = transport.query(makeSlice(QUERY));

        EXPECT_EQ(DnsTlsTransport::Response::success, r.code);
        EXPECT_EQ(QUERY, r.response);
    }
}

// Returning null from the factory indicates a connection failure.
class NullSocketFactory : public IDnsTlsSocketFactory {
public:
    NullSocketFactory() {}
    std::unique_ptr<IDnsTlsSocket> createDnsTlsSocket(
            const DnsTlsServer& server ATTRIBUTE_UNUSED,
            unsigned mark ATTRIBUTE_UNUSED,
            DnsTlsSessionCache* cache ATTRIBUTE_UNUSED) override {
        return nullptr;
    }
};

TEST_F(TransportTest, ConnectFail) {
    NullSocketFactory factory;
    DnsTlsTransport transport(SERVER1, MARK, &factory);
    auto r = transport.query(makeSlice(QUERY));

    EXPECT_EQ(DnsTlsTransport::Response::network_error, r.code);
    EXPECT_TRUE(r.response.empty());
}

// Dispatcher tests
class DispatcherTest : public BaseTest {};

TEST_F(DispatcherTest, Query) {
    bytevec ans(4096);
    int resplen = 0;

    auto factory = std::make_unique<FakeSocketFactory<FakeSocketEcho>>();
    DnsTlsDispatcher dispatcher(std::move(factory));
    auto r = dispatcher.query(SERVER1, MARK, makeSlice(QUERY),
                              makeSlice(ans), &resplen);

    EXPECT_EQ(DnsTlsTransport::Response::success, r);
    EXPECT_EQ(int(QUERY.size()), resplen);
    ans.resize(resplen);
    EXPECT_EQ(QUERY, ans);
}

TEST_F(DispatcherTest, AnswerTooLarge) {
    bytevec ans(SIZE - 1);  // Too small to hold the answer
    int resplen = 0;

    auto factory = std::make_unique<FakeSocketFactory<FakeSocketEcho>>();
    DnsTlsDispatcher dispatcher(std::move(factory));
    auto r = dispatcher.query(SERVER1, MARK, makeSlice(QUERY),
                              makeSlice(ans), &resplen);

    EXPECT_EQ(DnsTlsTransport::Response::limit_error, r);
}

template<class T>
class TrackingFakeSocketFactory : public IDnsTlsSocketFactory {
public:
    TrackingFakeSocketFactory() {}
    std::unique_ptr<IDnsTlsSocket> createDnsTlsSocket(
            const DnsTlsServer& server,
            unsigned mark,
            DnsTlsSessionCache* cache ATTRIBUTE_UNUSED) override {
        std::lock_guard<std::mutex> guard(mLock);
        keys.emplace(mark, server);
        return std::make_unique<T>();
    }
    std::multiset<std::pair<unsigned, DnsTlsServer>> keys;
private:
    std::mutex mLock;
};

TEST_F(DispatcherTest, Dispatching) {
    auto factory = std::make_unique<TrackingFakeSocketFactory<FakeSocketEcho>>();
    auto* weak_factory = factory.get();  // Valid as long as dispatcher is in scope.
    DnsTlsDispatcher dispatcher(std::move(factory));

    // Populate a vector of two servers and two socket marks, four combinations
    // in total.
    std::vector<std::pair<unsigned, DnsTlsServer>> keys;
    keys.emplace_back(MARK, SERVER1);
    keys.emplace_back(MARK + 1, SERVER1);
    keys.emplace_back(MARK, V4ADDR2);
    keys.emplace_back(MARK + 1, V4ADDR2);

    // Do one query on each server.  They should all succeed.
    std::vector<std::thread> threads;
    for (size_t i = 0; i < keys.size(); ++i) {
        auto key = keys[i % keys.size()];
        threads.emplace_back([key, i] (DnsTlsDispatcher* dispatcher) {
            auto q = make_query(i, SIZE);
            bytevec ans(4096);
            int resplen = 0;
            unsigned mark = key.first;
            const DnsTlsServer& server = key.second;
            auto r = dispatcher->query(server, mark, makeSlice(q),
                                       makeSlice(ans), &resplen);
            EXPECT_EQ(DnsTlsTransport::Response::success, r);
            EXPECT_EQ(int(q.size()), resplen);
            ans.resize(resplen);
            EXPECT_EQ(q, ans);
        }, &dispatcher);
    }
    for (auto& thread : threads) {
        thread.join();
    }
    // We expect that the factory created one socket for each key.
    EXPECT_EQ(keys.size(), weak_factory->keys.size());
    for (auto& key : keys) {
        EXPECT_EQ(1U, weak_factory->keys.count(key));
    }
}

} // end of namespace net
} // end of namespace android
