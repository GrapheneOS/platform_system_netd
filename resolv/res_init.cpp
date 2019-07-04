/*	$NetBSD: res_init.c,v 1.8 2006/03/19 03:10:08 christos Exp $	*/

/*
 * Copyright (c) 1985, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define LOG_TAG "resolv"

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

#include <android-base/logging.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netd_resolv/resolv.h"
#include "res_state_ext.h"
#include "resolv_private.h"

/*
 * Resolver state default settings.
 */

/*
 * Set up default settings.  If the configuration file exist, the values
 * there will have precedence.  Otherwise, the server address is set to
 * INADDR_ANY and the default domain name comes from the gethostname().
 *
 * An interrim version of this code (BIND 4.9, pre-4.4BSD) used 127.0.0.1
 * rather than INADDR_ANY ("0.0.0.0") as the default name server address
 * since it was noted that INADDR_ANY actually meant ``the first interface
 * you "ifconfig"'d at boot time'' and if this was a SLIP or PPP interface,
 * it had to be "up" in order for you to reach your own name server.  It
 * was later decided that since the recommended practice is to always
 * install local static routes through 127.0.0.1 for all your network
 * interfaces, that we could solve this problem without a code change.
 *
 * The configuration file should always be used, since it is the only way
 * to specify a default domain.  If you are running a server on your local
 * machine, you should say "nameserver 0.0.0.0" or "nameserver 127.0.0.1"
 * in the configuration file.
 *
 * Return 0 if completes successfully, -1 on error
 */
int res_ninit(res_state statp) {
    return res_vinit(statp, 0);
}

/* This function has to be reachable by res_data.c but not publicly. */
int res_vinit(res_state statp, int preinit) {
    int nserv = 0; /* number of nameserver records read from file */
    sockaddr_union u[2];

    if ((statp->options & RES_INIT) != 0U) res_ndestroy(statp);

    if (!preinit) {
        statp->netid = NETID_UNSET;
        statp->options = RES_DEFAULT;
        statp->id = arc4random_uniform(65536);
        statp->_mark = MARK_UNSET;
    }

    memset(u, 0, sizeof(u));
    u[nserv].sin.sin_addr.s_addr = INADDR_ANY;
    u[nserv].sin.sin_family = AF_INET;
    u[nserv].sin.sin_port = htons(NAMESERVER_PORT);
    nserv++;
    statp->nscount = 0;
    statp->ndots = 1;
    statp->_vcsock = -1;
    statp->_flags = 0;
    statp->_u._ext.nscount = 0;
    statp->_u._ext.ext = (res_state_ext*) malloc(sizeof(*statp->_u._ext.ext));
    statp->use_local_nameserver = false;
    if (statp->_u._ext.ext != NULL) {
        memset(statp->_u._ext.ext, 0, sizeof(*statp->_u._ext.ext));
        statp->_u._ext.ext->nsaddrs[0].sin = statp->nsaddr;
        strcpy(statp->_u._ext.ext->nsuffix, "ip6.arpa");
        strcpy(statp->_u._ext.ext->nsuffix2, "ip6.int");
    }
    statp->nsort = 0;
    res_setservers(statp, u, nserv);

    if (nserv > 0) {
        statp->nscount = nserv;
        statp->options |= RES_INIT;
    }
    return (0);
}


/*
 * This routine is for closing the socket if a virtual circuit is used and
 * the program wants to close it.  This provides support for endhostent()
 * which expects to close the socket.
 *
 * This routine is not expected to be user visible.
 */
void res_nclose(res_state statp) {
    int ns;

    if (statp->_vcsock >= 0) {
        (void) close(statp->_vcsock);
        statp->_vcsock = -1;
        statp->_flags &= ~RES_F_VC;
    }
    for (ns = 0; ns < statp->_u._ext.nscount; ns++) {
        if (statp->_u._ext.nssocks[ns] != -1) {
            (void) close(statp->_u._ext.nssocks[ns]);
            statp->_u._ext.nssocks[ns] = -1;
        }
    }
}

void res_ndestroy(res_state statp) {
    res_nclose(statp);
    if (statp->_u._ext.ext != NULL) free(statp->_u._ext.ext);
    statp->options &= ~RES_INIT;
    statp->_u._ext.ext = NULL;
}

void res_setservers(res_state statp, const sockaddr_union* set, int cnt) {
    int i, nserv;
    size_t size;

    /* close open servers */
    res_nclose(statp);

    /* cause rtt times to be forgotten */
    statp->_u._ext.nscount = 0;

    nserv = 0;
    for (i = 0; i < cnt && nserv < MAXNS; i++) {
        switch (set->sin.sin_family) {
            case AF_INET:
                size = sizeof(set->sin);
                if (statp->_u._ext.ext)
                    memcpy(&statp->_u._ext.ext->nsaddrs[nserv], &set->sin, size);
                if (size <= sizeof(statp->nsaddr_list[nserv]))
                    memcpy(&statp->nsaddr_list[nserv], &set->sin, size);
                else
                    statp->nsaddr_list[nserv].sin_family = 0;
                nserv++;
                break;

#ifdef HAS_INET6_STRUCTS
            case AF_INET6:
                size = sizeof(set->sin6);
                if (statp->_u._ext.ext)
                    memcpy(&statp->_u._ext.ext->nsaddrs[nserv], &set->sin6, size);
                if (size <= sizeof(statp->nsaddr_list[nserv]))
                    memcpy(&statp->nsaddr_list[nserv], &set->sin6, size);
                else
                    statp->nsaddr_list[nserv].sin_family = 0;
                nserv++;
                break;
#endif

            default:
                break;
        }
        set++;
    }
    statp->nscount = nserv;
}

int res_getservers(res_state statp, sockaddr_union* set, int cnt) {
    int i;
    size_t size;
    uint16_t family;

    for (i = 0; i < statp->nscount && i < cnt; i++) {
        if (statp->_u._ext.ext)
            family = statp->_u._ext.ext->nsaddrs[i].sin.sin_family;
        else
            family = statp->nsaddr_list[i].sin_family;

        switch (family) {
            case AF_INET:
                size = sizeof(set->sin);
                if (statp->_u._ext.ext)
                    memcpy(&set->sin, &statp->_u._ext.ext->nsaddrs[i], size);
                else
                    memcpy(&set->sin, &statp->nsaddr_list[i], size);
                break;

#ifdef HAS_INET6_STRUCTS
            case AF_INET6:
                size = sizeof(set->sin6);
                if (statp->_u._ext.ext)
                    memcpy(&set->sin6, &statp->_u._ext.ext->nsaddrs[i], size);
                else
                    memcpy(&set->sin6, &statp->nsaddr_list[i], size);
                break;
#endif

            default:
                set->sin.sin_family = 0;
                break;
        }
        set++;
    }
    return (statp->nscount);
}

void res_setnetcontext(res_state statp, const struct android_net_context* netcontext,
                       android::net::NetworkDnsEventReported* _Nonnull event) {
    if (statp != NULL) {
        statp->netid = netcontext->dns_netid;
        statp->uid = netcontext->uid;
        statp->_mark = netcontext->dns_mark;
        if (netcontext->flags & NET_CONTEXT_FLAG_USE_EDNS) {
            statp->options |= RES_USE_EDNS0 | RES_USE_DNSSEC;
        }
        if (netcontext->flags & NET_CONTEXT_FLAG_USE_LOCAL_NAMESERVERS) {
            statp->use_local_nameserver = true;
        }
        statp->event = event;
    }
}
