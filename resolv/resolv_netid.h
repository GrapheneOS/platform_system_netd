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
#ifndef _RESOLV_NETID_H
#define _RESOLV_NETID_H

/* This header contains declarations related to per-network DNS
 * server selection. They are used by system/netd/ and should not be
 * exposed by the C library's public NDK headers.
 */
#include <netinet/in.h>
#include <stdio.h>

#include "resolv_params.h"

/*
 * Passing NETID_UNSET as the netId causes system/netd/server/DnsProxyListener.cpp to
 * fill in the appropriate default netId for the query.
 */
#define NETID_UNSET 0u

/*
 * MARK_UNSET represents the default (i.e. unset) value for a socket mark.
 */
#define MARK_UNSET 0u

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
    res_send_qhook qhook;
};

#define NET_CONTEXT_INVALID_UID ((uid_t) -1)

#define NET_CONTEXT_FLAG_USE_LOCAL_NAMESERVERS 0x00000001
#define NET_CONTEXT_FLAG_USE_EDNS 0x00000002

LIBNETD_RESOLV_PUBLIC hostent* android_gethostbyaddrfornet(const void*, socklen_t, int, unsigned,
                                                           unsigned);
LIBNETD_RESOLV_PUBLIC hostent* android_gethostbynamefornet(const char*, int, unsigned, unsigned);
LIBNETD_RESOLV_PUBLIC int android_getaddrinfofornet(const char*, const char*,
                                                    const addrinfo*, unsigned, unsigned,
                                                    addrinfo**);
/*
 * TODO: consider refactoring android_getaddrinfo_proxy() to serve as an
 * explore_fqdn() dispatch table method, with the below function only making DNS calls.
 */
LIBNETD_RESOLV_PUBLIC hostent* android_gethostbyaddrfornetcontext(const void*, socklen_t, int,
                                                                  const android_net_context*);
LIBNETD_RESOLV_PUBLIC hostent* android_gethostbynamefornetcontext(const char*, int,
                                                                  const android_net_context*);
LIBNETD_RESOLV_PUBLIC int android_getaddrinfofornetcontext(const char*, const char*,
                                                           const addrinfo*,
                                                           const android_net_context*, addrinfo**);

// Set name servers for a network
LIBNETD_RESOLV_PUBLIC int _resolv_set_nameservers_for_net(unsigned netid, const char** servers,
                                                          unsigned numservers, const char* domains,
                                                          const __res_params* params);

// Flush the cache associated with a certain network
LIBNETD_RESOLV_PUBLIC void _resolv_flush_cache_for_net(unsigned netid);

// Delete the cache associated with a certain network
LIBNETD_RESOLV_PUBLIC void _resolv_delete_cache_for_net(unsigned netid);

#endif /* _RESOLV_NETID_H */
