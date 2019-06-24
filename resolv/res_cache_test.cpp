/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <atomic>
#include <chrono>
#include <ctime>
#include <thread>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android/multinetwork.h>

#include "dns_responder/dns_responder.h"
#include "resolv_cache.h"
#include "resolv_private.h"

using namespace std::chrono_literals;

constexpr int TEST_NETID = 30;
constexpr int TEST_NETID_2 = 31;

// Constant values sync'd from res_cache.cpp
constexpr int DNS_HEADER_SIZE = 12;
constexpr int MAX_ENTRIES = 64 * 2 * 5;
constexpr int MAXPACKET = 8 * 1024;

namespace {

struct CacheEntry {
    std::vector<char> query;
    std::vector<char> answer;
};

std::vector<char> makeQuery(int op, const char* qname, int qclass, int qtype) {
    res_state res = res_get_state();
    uint8_t buf[MAXPACKET] = {};
    const int len = res_nmkquery(res, op, qname, qclass, qtype, NULL, 0, NULL, buf, sizeof(buf));
    return std::vector<char>(buf, buf + len);
}

std::vector<char> makeAnswer(const std::vector<char>& query, const char* rdata_str,
                             const unsigned ttl) {
    test::DNSHeader header;
    header.read(query.data(), query.data() + query.size());

    for (const test::DNSQuestion& question : header.questions) {
        std::string rname(question.qname.name);
        test::DNSRecord record{
                .name = {.name = question.qname.name},
                .rtype = question.qtype,
                .rclass = question.qclass,
                .ttl = ttl,
        };
        test::DNSResponder::fillAnswerRdata(rdata_str, record);
        header.answers.push_back(std::move(record));
    }

    char answer[MAXPACKET] = {};
    char* answer_end = header.write(answer, answer + sizeof(answer));
    return std::vector<char>(answer, answer_end);
}

// Get the current time in unix timestamp since the Epoch.
time_t currentTime() {
    return std::time(nullptr);
}

}  // namespace

class ResolvCacheTest : public ::testing::Test {
  protected:
    ResolvCacheTest() {
        // Store the default one and conceal 10000+ lines of resolver cache logs.
        defaultLogSeverity = android::base::SetMinimumLogSeverity(
                static_cast<android::base::LogSeverity>(android::base::WARNING));
    }
    ~ResolvCacheTest() {
        cacheDelete(TEST_NETID);
        cacheDelete(TEST_NETID_2);

        // Restore the log severity.
        android::base::SetMinimumLogSeverity(defaultLogSeverity);
    }

    [[nodiscard]] bool cacheLookup(ResolvCacheStatus expectedCacheStatus, uint32_t netId,
                                   const CacheEntry& ce, uint32_t flags = 0) {
        int anslen = 0;
        std::vector<char> answer(MAXPACKET);
        const auto cacheStatus = resolv_cache_lookup(netId, ce.query.data(), ce.query.size(),
                                                     answer.data(), answer.size(), &anslen, flags);
        if (cacheStatus != expectedCacheStatus) {
            ADD_FAILURE() << "cacheStatus: expected = " << expectedCacheStatus
                          << ", actual =" << cacheStatus;
            return false;
        }

        if (cacheStatus == RESOLV_CACHE_FOUND) {
            answer.resize(anslen);
            if (answer != ce.answer) {
                ADD_FAILURE() << "The answer from the cache is not as expected.";
                return false;
            }
        }
        return true;
    }

    int cacheCreate(uint32_t netId) {
        return resolv_create_cache_for_net(netId);
    }

    void cacheDelete(uint32_t netId) {
        resolv_delete_cache_for_net(netId);
    }

    int cacheAdd(uint32_t netId, const CacheEntry& ce) {
        return resolv_cache_add(netId, ce.query.data(), ce.query.size(), ce.answer.data(),
                                ce.answer.size());
    }

    int cacheAdd(uint32_t netId, const std::vector<char>& query, const std::vector<char>& answer) {
        return resolv_cache_add(netId, query.data(), query.size(), answer.data(), answer.size());
    }

    int cacheGetExpiration(uint32_t netId, const std::vector<char>& query, time_t* expiration) {
        return resolv_cache_get_expiration(netId, query, expiration);
    }

    void cacheQueryFailed(uint32_t netId, const CacheEntry& ce, uint32_t flags) {
        _resolv_cache_query_failed(netId, ce.query.data(), ce.query.size(), flags);
    }

    CacheEntry makeCacheEntry(int op, const char* qname, int qclass, int qtype, const char* rdata,
                              std::chrono::seconds ttl = 10s) {
        CacheEntry ce;
        ce.query = makeQuery(op, qname, qclass, qtype);
        ce.answer = makeAnswer(ce.query, rdata, static_cast<unsigned>(ttl.count()));
        return ce;
    }

  private:
    android::base::LogSeverity defaultLogSeverity;
};

TEST_F(ResolvCacheTest, CreateAndDeleteCache) {
    // Create the cache for network 1.
    EXPECT_EQ(0, cacheCreate(TEST_NETID));
    EXPECT_EQ(-EEXIST, cacheCreate(TEST_NETID));
    EXPECT_TRUE(has_named_cache(TEST_NETID));

    // Create the cache for network 2.
    EXPECT_EQ(0, cacheCreate(TEST_NETID_2));
    EXPECT_EQ(-EEXIST, cacheCreate(TEST_NETID_2));
    EXPECT_TRUE(has_named_cache(TEST_NETID_2));

    // Delete the cache in network 1.
    cacheDelete(TEST_NETID);
    EXPECT_FALSE(has_named_cache(TEST_NETID));
    EXPECT_TRUE(has_named_cache(TEST_NETID_2));
}

// Missing checks for the argument 'answer'.
TEST_F(ResolvCacheTest, CacheAdd_InvalidArgs) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));

    const std::vector<char> queryEmpty(MAXPACKET, 0);
    const std::vector<char> queryTooSmall(DNS_HEADER_SIZE - 1, 0);
    CacheEntry ce = makeCacheEntry(QUERY, "valid.cache", ns_c_in, ns_t_a, "1.2.3.4");

    EXPECT_EQ(-EINVAL, cacheAdd(TEST_NETID, queryEmpty, ce.answer));
    EXPECT_EQ(-EINVAL, cacheAdd(TEST_NETID, queryTooSmall, ce.answer));

    // Cache not existent in TEST_NETID_2.
    EXPECT_EQ(-ENONET, cacheAdd(TEST_NETID_2, ce));
}

TEST_F(ResolvCacheTest, CacheAdd_DuplicateEntry) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));
    CacheEntry ce = makeCacheEntry(QUERY, "existent.in.cache", ns_c_in, ns_t_a, "1.2.3.4");
    time_t now = currentTime();

    // Add the cache entry.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));

    // Get the expiration time and verify its value is greater than now.
    time_t expiration1;
    EXPECT_EQ(0, cacheGetExpiration(TEST_NETID, ce.query, &expiration1));
    EXPECT_GT(expiration1, now);

    // Adding the duplicate entry will return an error, and the expiration time won't be modified.
    EXPECT_EQ(-EEXIST, cacheAdd(TEST_NETID, ce));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));
    time_t expiration2;
    EXPECT_EQ(0, cacheGetExpiration(TEST_NETID, ce.query, &expiration2));
    EXPECT_EQ(expiration1, expiration2);
}

TEST_F(ResolvCacheTest, CacheLookup) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));
    EXPECT_EQ(0, cacheCreate(TEST_NETID_2));
    CacheEntry ce = makeCacheEntry(QUERY, "existent.in.cache", ns_c_in, ns_t_a, "1.2.3.4");

    // Cache found in network 1.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));

    // No cache found in network 2.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID_2, ce));

    ce = makeCacheEntry(QUERY, "existent.in.cache", ns_c_in, ns_t_aaaa, "2001:db8::1.2.3.4");

    // type A and AAAA are independent.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));
}

TEST_F(ResolvCacheTest, CacheLookup_CacheFlags) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));
    std::vector<char> answerFromCache;
    CacheEntry ce = makeCacheEntry(QUERY, "existent.in.cache", ns_c_in, ns_t_a, "1.2.3.4");

    // The entry can't be found when only no-cache-lookup bit is carried.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce, ANDROID_RESOLV_NO_CACHE_LOOKUP));

    // Ensure RESOLV_CACHE_SKIP is returned when there's no such the same entry in the cache.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_SKIP, TEST_NETID, ce, ANDROID_RESOLV_NO_CACHE_STORE));

    // Skip the cache lookup if no-cache-lookup and no-cache-store bits are carried
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_SKIP, TEST_NETID, ce,
                            ANDROID_RESOLV_NO_CACHE_LOOKUP | ANDROID_RESOLV_NO_CACHE_STORE));

    // Add the cache entry.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));

    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce, ANDROID_RESOLV_NO_CACHE_LOOKUP));

    // Now no-cache-store has no effect if a same entry is existent in the cache.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce, ANDROID_RESOLV_NO_CACHE_STORE));

    // Skip the cache lookup again regardless of a same entry being already in the cache.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_SKIP, TEST_NETID, ce,
                            ANDROID_RESOLV_NO_CACHE_LOOKUP | ANDROID_RESOLV_NO_CACHE_STORE));
}

TEST_F(ResolvCacheTest, CacheLookup_Types) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));
    static const struct QueryTypes {
        int type;
        std::string rdata;
    } Types[] = {
            {ns_t_a, "1.2.3.4"},
            {ns_t_aaaa, "2001:db8::1.2.3.4"},
            {ns_t_ptr, "4.3.2.1.in-addr.arpa."},
            {ns_t_ptr, "4.0.3.0.2.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
    };

    for (const auto& t : Types) {
        std::string name = android::base::StringPrintf("cache.lookup.type.%s", t.rdata.c_str());
        SCOPED_TRACE(name);

        CacheEntry ce = makeCacheEntry(QUERY, name.data(), ns_c_in, t.type, t.rdata.data());
        EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));
        EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));
        EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));
    }
}

TEST_F(ResolvCacheTest, CacheLookup_InvalidArgs) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));

    const std::vector<char> queryEmpty(MAXPACKET, 0);
    const std::vector<char> queryTooSmall(DNS_HEADER_SIZE - 1, 0);
    std::vector<char> answerTooSmall(DNS_HEADER_SIZE - 1, 0);
    const CacheEntry ce = makeCacheEntry(QUERY, "valid.cache", ns_c_in, ns_t_a, "1.2.3.4");
    auto cacheLookupFn = [](const std::vector<char>& query,
                            std::vector<char> answer) -> ResolvCacheStatus {
        int anslen = 0;
        return resolv_cache_lookup(TEST_NETID, query.data(), query.size(), answer.data(),
                                   answer.size(), &anslen, 0);
    };

    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));

    EXPECT_EQ(RESOLV_CACHE_UNSUPPORTED, cacheLookupFn(queryEmpty, ce.answer));
    EXPECT_EQ(RESOLV_CACHE_UNSUPPORTED, cacheLookupFn(queryTooSmall, ce.answer));
    EXPECT_EQ(RESOLV_CACHE_UNSUPPORTED, cacheLookupFn(ce.query, answerTooSmall));

    // It can actually be found with valid arguments.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));

    // Cache not existent in TEST_NETID_2.
    EXPECT_EQ(-ENONET, cacheAdd(TEST_NETID_2, ce));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_UNSUPPORTED, TEST_NETID_2, ce));
}

TEST_F(ResolvCacheTest, CacheLookup_Expired) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));

    // An entry with zero ttl won't be stored in the cache.
    CacheEntry ce = makeCacheEntry(QUERY, "expired.in.0s", ns_c_in, ns_t_a, "1.2.3.4", 0s);
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));

    // Create an entry expired in 1s.
    ce = makeCacheEntry(QUERY, "expired.in.1s", ns_c_in, ns_t_a, "1.2.3.4", 1s);
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));

    // Cache found.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));
    time_t expiration;
    EXPECT_EQ(0, cacheGetExpiration(TEST_NETID, ce.query, &expiration));

    // Wait for the cache expired.
    std::this_thread::sleep_for(1500ms);
    EXPECT_GE(currentTime(), expiration);
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));
}

TEST_F(ResolvCacheTest, PendingRequest_QueryDeferred) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));
    EXPECT_EQ(0, cacheCreate(TEST_NETID_2));

    CacheEntry ce = makeCacheEntry(QUERY, "query.deferred", ns_c_in, ns_t_a, "1.2.3.4");
    std::atomic_bool done(false);

    // This is the first lookup. The following lookups from other threads will be in the
    // pending request list.
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));

    std::vector<std::thread> threads(5);
    for (std::thread& thread : threads) {
        thread = std::thread([&]() {
            EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));

            // Ensure this thread gets stuck in lookups before we wake it.
            EXPECT_TRUE(done);
        });
    }

    // Wait for a while for the threads performing lookups.
    // TODO: Perhaps implement a test-only function to get the number of pending requests
    // instead of sleep.
    std::this_thread::sleep_for(100ms);

    // The threads keep waiting regardless of any other networks or even if cache flag is set.
    EXPECT_EQ(0, cacheAdd(TEST_NETID_2, ce));
    cacheQueryFailed(TEST_NETID, ce, ANDROID_RESOLV_NO_CACHE_STORE);
    cacheQueryFailed(TEST_NETID, ce, ANDROID_RESOLV_NO_CACHE_LOOKUP);
    cacheQueryFailed(TEST_NETID_2, ce, ANDROID_RESOLV_NO_CACHE_STORE);
    cacheQueryFailed(TEST_NETID_2, ce, ANDROID_RESOLV_NO_CACHE_LOOKUP);
    cacheDelete(TEST_NETID_2);

    // Ensure none of the threads has finished the lookups.
    std::this_thread::sleep_for(100ms);

    // Wake up the threads
    done = true;
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));

    for (std::thread& thread : threads) {
        thread.join();
    }
}

TEST_F(ResolvCacheTest, PendingRequest_QueryFailed) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));

    CacheEntry ce = makeCacheEntry(QUERY, "query.failed", ns_c_in, ns_t_a, "1.2.3.4");
    std::atomic_bool done(false);

    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));

    std::vector<std::thread> threads(5);
    for (std::thread& thread : threads) {
        thread = std::thread([&]() {
            EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));

            // Ensure this thread gets stuck in lookups before we wake it.
            EXPECT_TRUE(done);
        });
    }

    // Wait for a while for the threads performing lookups.
    std::this_thread::sleep_for(100ms);

    // Wake up the threads
    done = true;
    cacheQueryFailed(TEST_NETID, ce, 0);

    for (std::thread& thread : threads) {
        thread.join();
    }
}

TEST_F(ResolvCacheTest, PendingRequest_CacheDestroyed) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));
    EXPECT_EQ(0, cacheCreate(TEST_NETID_2));

    CacheEntry ce = makeCacheEntry(QUERY, "query.failed", ns_c_in, ns_t_a, "1.2.3.4");
    std::atomic_bool done(false);

    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));

    std::vector<std::thread> threads(5);
    for (std::thread& thread : threads) {
        thread = std::thread([&]() {
            EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce));

            // Ensure this thread gets stuck in lookups before we wake it.
            EXPECT_TRUE(done);
        });
    }

    // Wait for a while for the threads performing lookups.
    std::this_thread::sleep_for(100ms);

    // Deleting another network must not cause the threads to wake up.
    cacheDelete(TEST_NETID_2);

    // Ensure none of the threads has finished the lookups.
    std::this_thread::sleep_for(100ms);

    // Wake up the threads
    done = true;
    cacheDelete(TEST_NETID);

    for (std::thread& thread : threads) {
        thread.join();
    }
}

TEST_F(ResolvCacheTest, MaxEntries) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));
    std::vector<CacheEntry> ces;

    for (int i = 0; i < 2 * MAX_ENTRIES; i++) {
        std::string qname = android::base::StringPrintf("cache.%04d", i);
        SCOPED_TRACE(qname);
        CacheEntry ce = makeCacheEntry(QUERY, qname.data(), ns_c_in, ns_t_a, "1.2.3.4");
        EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));
        EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));
        ces.emplace_back(ce);
    }

    for (int i = 0; i < 2 * MAX_ENTRIES; i++) {
        std::string qname = android::base::StringPrintf("cache.%04d", i);
        SCOPED_TRACE(qname);
        if (i < MAX_ENTRIES) {
            // Because the cache is LRU, the oldest queries should have been purged,
            // and the most recent MAX_ENTRIES ones should still be present.
            EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ces[i]));
        } else {
            EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ces[i]));
        }
    }
}

TEST_F(ResolvCacheTest, CacheFull) {
    EXPECT_EQ(0, cacheCreate(TEST_NETID));

    CacheEntry ce1 = makeCacheEntry(QUERY, "cache.0000", ns_c_in, ns_t_a, "1.2.3.4", 100s);
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce1));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce1));

    CacheEntry ce2 = makeCacheEntry(QUERY, "cache.0001", ns_c_in, ns_t_a, "1.2.3.4", 1s);
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce2));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce2));

    // Stuff the resolver cache.
    for (int i = 2; i < MAX_ENTRIES; i++) {
        std::string qname = android::base::StringPrintf("cache.%04d", i);
        SCOPED_TRACE(qname);
        CacheEntry ce = makeCacheEntry(QUERY, qname.data(), ns_c_in, ns_t_a, "1.2.3.4", 50s);
        EXPECT_EQ(0, cacheAdd(TEST_NETID, ce));
        EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce));
    }

    // Wait for ce2 expired.
    std::this_thread::sleep_for(1500ms);

    // The cache is full now, and the expired ce2 will be removed first.
    CacheEntry ce3 = makeCacheEntry(QUERY, "cache.overfilled.1", ns_c_in, ns_t_a, "1.2.3.4", 50s);
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce3));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce3));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce2));

    // The cache is full again but there's no one expired, so the oldest ce1 will be removed.
    CacheEntry ce4 = makeCacheEntry(QUERY, "cache.overfilled.2", ns_c_in, ns_t_a, "1.2.3.4", 50s);
    EXPECT_EQ(0, cacheAdd(TEST_NETID, ce4));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_FOUND, TEST_NETID, ce4));
    EXPECT_TRUE(cacheLookup(RESOLV_CACHE_NOTFOUND, TEST_NETID, ce1));
}

// TODO: Tests for struct resolv_cache_info, including:
//     - res_params
//         -- resolv_cache_get_resolver_stats()
//     - res_stats
//         -- _resolv_cache_add_resolver_stats_sample()
//         -- android_net_res_stats_get_info_for_net()
// TODO: inject a mock timer into the cache to make TTL tests pass instantly
// TODO: test TTL of RFC 2308 negative caching
