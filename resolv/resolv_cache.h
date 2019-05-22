/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

#include "netd_resolv/resolv.h"

#include <stddef.h>

#include <vector>

struct __res_state;
struct resolv_cache;

/* sets the name server addresses to the provided res_state structure. The
 * name servers are retrieved from the cache which is associated
 * with the network to which the res_state structure is associated */
void _resolv_populate_res_for_net(struct __res_state* statp);

std::vector<unsigned> resolv_list_caches();

typedef enum {
    RESOLV_CACHE_UNSUPPORTED, /* the cache can't handle that kind of queries */
                              /* or the answer buffer is too small */
    RESOLV_CACHE_NOTFOUND,    /* the cache doesn't know about this query */
    RESOLV_CACHE_FOUND,       /* the cache found the answer */
    RESOLV_CACHE_SKIP         /* Don't do anything on cache */
} ResolvCacheStatus;

ResolvCacheStatus resolv_cache_lookup(unsigned netid, const void* query, int querylen, void* answer,
                                      int answersize, int* answerlen, uint32_t flags);

// add a (query,answer) to the cache. If the pair has been in the cache, no new entry will be added
// in the cache.
int resolv_cache_add(unsigned netid, const void* query, int querylen, const void* answer,
                     int answerlen);

/* Notify the cache a request failed */
void _resolv_cache_query_failed(unsigned netid, const void* query, int querylen, uint32_t flags);

// Sets name servers for a given network.
int resolv_set_nameservers(unsigned netid, const std::vector<std::string>& servers,
                           const std::vector<std::string>& domains, const res_params& params);

// Creates the cache associated with the given network.
int resolv_create_cache_for_net(unsigned netid);

// Deletes the cache associated with the given network.
void resolv_delete_cache_for_net(unsigned netid);

// For test only.
// Return true if the cache is existent in the given network, false otherwise.
bool has_named_cache(unsigned netid);

// For test only.
// Get the expiration time of a cache entry. Return 0 on success; otherwise, an negative error is
// returned if the expiration time can't be acquired.
int resolv_cache_get_expiration(unsigned netid, const std::vector<char>& query, time_t* expiration);
