/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef NETD_RESOLV_RESOLV_STUB_H
#define NETD_RESOLV_RESOLV_STUB_H

#include "resolv.h"
#include "stats.h"

// Struct containing function pointers for every function exported by libnetd_resolv.
extern struct ResolvStub {
    int (*android_getaddrinfofornetcontext)(const char*, const char*, const addrinfo*,
                                            const android_net_context*, addrinfo**);

    int (*android_gethostbyaddrfornetcontext)(const void*, socklen_t, int,
                                              const android_net_context*, hostent**);

    int (*android_gethostbynamefornetcontext)(const char*, int, const android_net_context*,
                                              hostent**);

    void (*android_net_res_stats_aggregate)(res_stats* stats, int* successes, int* errors,
                                            int* timeouts, int* internal_errors, int* rtt_avg,
                                            time_t* last_sample_time);

    int (*android_net_res_stats_get_info_for_net)(unsigned netid, int* nscount,
                                                  sockaddr_storage servers[MAXNS], int* dcount,
                                                  char domains[MAXDNSRCH][MAXDNSRCHPATH],
                                                  __res_params* params, res_stats stats[MAXNS]);

    void (*android_net_res_stats_get_usable_servers)(const __res_params* params, res_stats stats[],
                                                     int nscount, bool valid_servers[]);

    void (*resolv_delete_cache_for_net)(unsigned netid);

    void (*resolv_delete_private_dns_for_net)(unsigned netid);

    void (*resolv_get_private_dns_status_for_net)(unsigned netid, ExternalPrivateDnsStatus* status);

    bool (*resolv_has_nameservers)(unsigned netid);

    bool (*resolv_init)(const dnsproxylistener_callbacks& callbacks);

    void (*resolv_register_private_dns_callback)(private_dns_validated_callback callback);

    int (*resolv_res_nsend)(const android_net_context* netContext, const u_char* msg, int msgLen,
                            u_char* ans, int ansLen, int* rcode, uint32_t flags);

    int (*resolv_set_nameservers_for_net)(unsigned netid, const char** servers, unsigned numservers,
                                          const char* domains, const __res_params* params);

    int (*resolv_set_private_dns_for_net)(unsigned netid, uint32_t mark, const char** servers,
                                          const unsigned numServers, const char* tlsName,
                                          const uint8_t** fingerprints,
                                          const unsigned numFingerprints);
} RESOLV_STUB;

int resolv_stub_init();

#endif  // NETD_RESOLV_RESOLV_STUB_H
