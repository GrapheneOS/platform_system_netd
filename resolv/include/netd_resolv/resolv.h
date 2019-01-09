/*
 * Copyright (C) 2014 The Android Open Source Project
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
#ifndef NETD_RESOLV_RESOLV_H
#define NETD_RESOLV_RESOLV_H

/*
 * This header contains declarations related to per-network DNS server selection.
 * They are used by system/netd/ and should not be exposed by the public NDK headers.
 */
#include <netinet/in.h>

#include "params.h"

typedef union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
} sockaddr_union;

/*
 * Passing NETID_UNSET as the netId causes system/netd/server/DnsProxyListener.cpp to
 * fill in the appropriate default netId for the query.
 */
#define NETID_UNSET 0u

/*
 * MARK_UNSET represents the default (i.e. unset) value for a socket mark.
 */
#define MARK_UNSET 0u

/*
 * Error code extending EAI_* codes defined in bionic/libc/include/netdb.h.
 * This error code, including EAI_*, returned from android_getaddrinfofornetcontext()
 * and android_gethostbynamefornetcontext() are used for DNS metrics.
 */
#define NETD_RESOLV_TIMEOUT 255  // consistent with RCODE_TIMEOUT

struct __res_params;
struct addrinfo;
struct hostent;

/*
 * A struct to capture context relevant to network operations.
 *
 * Application and DNS netids/marks can differ from one another under certain
 * circumstances, notably when a VPN applies to the given uid's traffic but the
 * VPN network does not have its own DNS servers explicitly provisioned.
 *
 * The introduction of per-UID routing means the uid is also an essential part
 * of the evaluation context. Its proper uninitialized value is
 * NET_CONTEXT_INVALID_UID.
 */
struct android_net_context {
    unsigned app_netid;
    unsigned app_mark;
    unsigned dns_netid;
    unsigned dns_mark;
    uid_t uid;
    unsigned flags;
};

#define NET_CONTEXT_INVALID_UID ((uid_t) -1)

#define NET_CONTEXT_FLAG_USE_LOCAL_NAMESERVERS 0x00000001
#define NET_CONTEXT_FLAG_USE_EDNS 0x00000002

struct ExternalPrivateDnsStatus {
    PrivateDnsMode mode;
    int numServers;
    struct PrivateDnsInfo {
        sockaddr_storage ss;
        const char* hostname;
        Validation validation;
    } serverStatus[MAXNS];
};

typedef void (*private_dns_validated_callback)(unsigned netid, const char* server,
                                               const char* hostname, bool success);

LIBNETD_RESOLV_PUBLIC hostent* android_gethostbyaddrfornetcontext(const void*, socklen_t, int,
                                                                  const android_net_context*);
LIBNETD_RESOLV_PUBLIC int android_gethostbynamefornetcontext(const char*, int,
                                                             const android_net_context*, hostent**);
LIBNETD_RESOLV_PUBLIC int android_getaddrinfofornetcontext(const char*, const char*,
                                                           const addrinfo*,
                                                           const android_net_context*, addrinfo**);

LIBNETD_RESOLV_PUBLIC bool resolv_has_nameservers(unsigned netid);

// Query dns with raw msg
// TODO: Add a way to control query parameter, like flags, or maybe res_options or even res_state.
LIBNETD_RESOLV_PUBLIC int resolv_res_nsend(const android_net_context* netContext, const u_char* msg,
                                           int msgLen, u_char* ans, int ansLen, int* rcode);

// Set name servers for a network
LIBNETD_RESOLV_PUBLIC int resolv_set_nameservers_for_net(unsigned netid, const char** servers,
                                                         int numservers, const char* domains,
                                                         const __res_params* params);

LIBNETD_RESOLV_PUBLIC int resolv_set_private_dns_for_net(unsigned netid, uint32_t mark,
                                                         const char** servers, int numServers,
                                                         const char* tlsName,
                                                         const uint8_t** fingerprints,
                                                         int numFingerprints);

LIBNETD_RESOLV_PUBLIC void resolv_delete_private_dns_for_net(unsigned netid);

LIBNETD_RESOLV_PUBLIC void resolv_get_private_dns_status_for_net(unsigned netid,
                                                                 ExternalPrivateDnsStatus* status);

// Register callback to listen whether private DNS validated
LIBNETD_RESOLV_PUBLIC void resolv_register_private_dns_callback(
        private_dns_validated_callback callback);

// Delete the cache associated with a certain network
LIBNETD_RESOLV_PUBLIC void resolv_delete_cache_for_net(unsigned netid);

#endif  // NETD_RESOLV_RESOLV_H
