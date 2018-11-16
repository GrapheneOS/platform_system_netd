/*	$NetBSD: gethnamaddr.c,v 1.91 2014/06/19 15:08:18 christos Exp $	*/

/*
 * ++Copyright++ 1985, 1988, 1993
 * -
 * Copyright (c) 1985, 1988, 1993
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
 * 3. Neither the name of the University nor the names of its contributors
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
 * -
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
 * -
 * --Copyright--
 */

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>
#include <functional>

#include "hostent.h"
#include "netd_resolv/resolv.h"
#include "resolv_cache.h"
#include "resolv_private.h"

// NetBSD uses _DIAGASSERT to null-check arguments and the like,
// but it's clear from the number of mistakes in their assertions
// that they don't actually test or ship with this.
#define _DIAGASSERT(e) /* nothing */

// TODO: unify macro ALIGNBYTES and ALIGN for all possible data type alignment of hostent
// buffer.
#define ALIGNBYTES (sizeof(uintptr_t) - 1)
#define ALIGN(p) (((uintptr_t)(p) + ALIGNBYTES) & ~ALIGNBYTES)

#ifndef LOG_AUTH
#define LOG_AUTH 0
#endif

#define MULTI_PTRS_ARE_ALIASES 1 /* XXX - experimental */

#define maybe_ok(res, nm, ok) (((res)->options & RES_NOCHECKNAME) != 0U || (ok)(nm) != 0)
#define maybe_hnok(res, hn) maybe_ok((res), (hn), res_hnok)
#define maybe_dnok(res, dn) maybe_ok((res), (dn), res_dnok)

#define addalias(d, s, arr, siz)                                            \
    do {                                                                    \
        if (d >= &arr[siz]) {                                               \
            char** xptr = (char**) realloc(arr, (siz + 10) * sizeof(*arr)); \
            if (xptr == NULL) goto nospc;                                   \
            d = xptr + (d - arr);                                           \
            arr = xptr;                                                     \
            siz += 10;                                                      \
        }                                                                   \
        *d++ = s;                                                           \
    } while (0)

static const char AskedForGot[] = "gethostby*.getanswer: asked for \"%s\", got \"%s\"";

#define MAXPACKET (8 * 1024)

typedef union {
    HEADER hdr;
    u_char buf[MAXPACKET];
} querybuf;

typedef union {
    int32_t al;
    char ac;
} align;

#ifdef DEBUG
static void debugprintf(const char*, res_state, ...) __attribute__((__format__(__printf__, 1, 3)));
#endif
static struct hostent* getanswer(const querybuf*, int, const char*, int, res_state, struct hostent*,
                                 char*, size_t, int*);
static void convert_v4v6_hostent(struct hostent* hp, char** bpp, char* ep,
                                 std::function<void(struct hostent* hp)> mapping_param,
                                 std::function<void(char* src, char* dst)> mapping_addr);
static void map_v4v6_address(const char*, char*);
static void map_v4v6_hostent(struct hostent*, char**, char*);
static void pad_v4v6_hostent(struct hostent* hp, char** bpp, char* ep);
static void addrsort(char**, int, res_state);

static bool _dns_gethtbyaddr(const unsigned char* uaddr, int len, int af,
                             const android_net_context* netcontext, getnamaddr* info);
static int _dns_gethtbyname(const char* name, int af, getnamaddr* info);

static int gethostbyname_internal(const char* name, int af, res_state res, hostent* hp, char* hbuf,
                                  size_t hbuflen, int* errorp,
                                  const android_net_context* netcontext);
static int gethostbyname_internal_real(const char* name, int af, res_state res, hostent* hp,
                                       char* buf, size_t buflen, int* he);
static struct hostent* android_gethostbyaddrfornetcontext_proxy_internal(
        const void*, socklen_t, int, struct hostent*, char*, size_t, int*,
        const struct android_net_context*);
static struct hostent* android_gethostbyaddrfornetcontext_proxy(
        const void* addr, socklen_t len, int af, const struct android_net_context* netcontext);

#ifdef DEBUG
static void debugprintf(const char* msg, res_state res, ...) {
    _DIAGASSERT(msg != NULL);

    if (res->options & RES_DEBUG) {
        int save = errno;
        va_list ap;

        va_start(ap, res);
        vprintf(msg, ap);
        va_end(ap);

        errno = save;
    }
}
#else
#define debugprintf(msg, res, num) /*nada*/
#endif

#define BOUNDED_INCR(x)      \
    do {                     \
        BOUNDS_CHECK(cp, x); \
        cp += (x);           \
    } while (0)

#define BOUNDS_CHECK(ptr, count)                     \
    do {                                             \
        if (eom - (ptr) < (count)) goto no_recovery; \
    } while (0)

static struct hostent* getanswer(const querybuf* answer, int anslen, const char* qname, int qtype,
                                 res_state res, struct hostent* hent, char* buf, size_t buflen,
                                 int* he) {
    const HEADER* hp;
    const u_char* cp;
    int n;
    size_t qlen;
    const u_char *eom, *erdata;
    char *bp, **ap, **hap, *ep;
    int ancount, qdcount;
    int haveanswer, had_error;
    int toobig = 0;
    char tbuf[MAXDNAME];
    char* addr_ptrs[MAXADDRS];
    const char* tname;
    int (*name_ok)(const char*);

    _DIAGASSERT(answer != NULL);
    _DIAGASSERT(qname != NULL);

    tname = qname;
    hent->h_name = NULL;
    eom = answer->buf + anslen;
    switch (qtype) {
        case T_A:
        case T_AAAA:
            name_ok = res_hnok;
            break;
        case T_PTR:
            name_ok = res_dnok;
            break;
        default:
            *he = NO_RECOVERY;
            return NULL; /* XXX should be abort(); */
    }

    size_t maxaliases = 10;
    char** aliases = (char**) malloc(maxaliases * sizeof(char*));
    if (!aliases) goto nospc;
    /*
     * find first satisfactory answer
     */
    hp = &answer->hdr;
    ancount = ntohs(hp->ancount);
    qdcount = ntohs(hp->qdcount);
    bp = buf;
    ep = buf + buflen;
    cp = answer->buf;
    BOUNDED_INCR(HFIXEDSZ);
    if (qdcount != 1) goto no_recovery;

    n = dn_expand(answer->buf, eom, cp, bp, (int) (ep - bp));
    if ((n < 0) || !maybe_ok(res, bp, name_ok)) goto no_recovery;

    BOUNDED_INCR(n + QFIXEDSZ);
    if (qtype == T_A || qtype == T_AAAA) {
        /* res_send() has already verified that the query name is the
         * same as the one we sent; this just gets the expanded name
         * (i.e., with the succeeding search-domain tacked on).
         */
        n = (int) strlen(bp) + 1; /* for the \0 */
        if (n >= MAXHOSTNAMELEN) goto no_recovery;
        hent->h_name = bp;
        bp += n;
        /* The qname can be abbreviated, but h_name is now absolute. */
        qname = hent->h_name;
    }
    hent->h_aliases = ap = aliases;
    hent->h_addr_list = hap = addr_ptrs;
    *ap = NULL;
    *hap = NULL;
    haveanswer = 0;
    had_error = 0;
    while (ancount-- > 0 && cp < eom && !had_error) {
        n = dn_expand(answer->buf, eom, cp, bp, (int) (ep - bp));
        if ((n < 0) || !maybe_ok(res, bp, name_ok)) {
            had_error++;
            continue;
        }
        cp += n; /* name */
        BOUNDS_CHECK(cp, 3 * INT16SZ + INT32SZ);
        int type = ns_get16(cp);
        cp += INT16SZ; /* type */
        int cl = ns_get16(cp);
        cp += INT16SZ + INT32SZ; /* class, TTL */
        n = ns_get16(cp);
        cp += INT16SZ; /* len */
        BOUNDS_CHECK(cp, n);
        erdata = cp + n;
        if (cl != C_IN) {
            /* XXX - debug? syslog? */
            cp += n;
            continue; /* XXX - had_error++ ? */
        }
        if ((qtype == T_A || qtype == T_AAAA) && type == T_CNAME) {
            n = dn_expand(answer->buf, eom, cp, tbuf, (int) sizeof tbuf);
            if ((n < 0) || !maybe_ok(res, tbuf, name_ok)) {
                had_error++;
                continue;
            }
            cp += n;
            if (cp != erdata) goto no_recovery;
            /* Store alias. */
            addalias(ap, bp, aliases, maxaliases);
            n = (int) strlen(bp) + 1; /* for the \0 */
            if (n >= MAXHOSTNAMELEN) {
                had_error++;
                continue;
            }
            bp += n;
            /* Get canonical name. */
            n = (int) strlen(tbuf) + 1; /* for the \0 */
            if (n > ep - bp || n >= MAXHOSTNAMELEN) {
                had_error++;
                continue;
            }
            strlcpy(bp, tbuf, (size_t)(ep - bp));
            hent->h_name = bp;
            bp += n;
            continue;
        }
        if (qtype == T_PTR && type == T_CNAME) {
            n = dn_expand(answer->buf, eom, cp, tbuf, (int) sizeof tbuf);
            if (n < 0 || !maybe_dnok(res, tbuf)) {
                had_error++;
                continue;
            }
            cp += n;
            if (cp != erdata) goto no_recovery;
            /* Get canonical name. */
            n = (int) strlen(tbuf) + 1; /* for the \0 */
            if (n > ep - bp || n >= MAXHOSTNAMELEN) {
                had_error++;
                continue;
            }
            strlcpy(bp, tbuf, (size_t)(ep - bp));
            tname = bp;
            bp += n;
            continue;
        }
        if (type != qtype) {
            if (type != T_KEY && type != T_SIG)
                syslog(LOG_NOTICE | LOG_AUTH,
                       "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"", qname,
                       p_class(C_IN), p_type(qtype), p_type(type));
            cp += n;
            continue; /* XXX - had_error++ ? */
        }
        switch (type) {
            case T_PTR:
                if (strcasecmp(tname, bp) != 0) {
                    syslog(LOG_NOTICE | LOG_AUTH, AskedForGot, qname, bp);
                    cp += n;
                    continue; /* XXX - had_error++ ? */
                }
                n = dn_expand(answer->buf, eom, cp, bp, (int) (ep - bp));
                if ((n < 0) || !maybe_hnok(res, bp)) {
                    had_error++;
                    break;
                }
#if MULTI_PTRS_ARE_ALIASES
                cp += n;
                if (cp != erdata) goto no_recovery;
                if (!haveanswer)
                    hent->h_name = bp;
                else
                    addalias(ap, bp, aliases, maxaliases);
                if (n != -1) {
                    n = (int) strlen(bp) + 1; /* for the \0 */
                    if (n >= MAXHOSTNAMELEN) {
                        had_error++;
                        break;
                    }
                    bp += n;
                }
                break;
#else
                hent->h_name = bp;
                if (res->options & RES_USE_INET6) {
                    n = strlen(bp) + 1; /* for the \0 */
                    if (n >= MAXHOSTNAMELEN) {
                        had_error++;
                        break;
                    }
                    bp += n;
                    map_v4v6_hostent(hent, &bp, ep);
                }
                goto success;
#endif
            case T_A:
            case T_AAAA:
                if (strcasecmp(hent->h_name, bp) != 0) {
                    syslog(LOG_NOTICE | LOG_AUTH, AskedForGot, hent->h_name, bp);
                    cp += n;
                    continue; /* XXX - had_error++ ? */
                }
                if (n != hent->h_length) {
                    cp += n;
                    continue;
                }
                if (type == T_AAAA) {
                    struct in6_addr in6;
                    memcpy(&in6, cp, NS_IN6ADDRSZ);
                    if (IN6_IS_ADDR_V4MAPPED(&in6)) {
                        cp += n;
                        continue;
                    }
                }
                if (!haveanswer) {
                    int nn;

                    hent->h_name = bp;
                    nn = (int) strlen(bp) + 1; /* for the \0 */
                    bp += nn;
                }

                bp += sizeof(align) - (size_t)((u_long) bp % sizeof(align));

                if (bp + n >= ep) {
                    debugprintf("size (%d) too big\n", res, n);
                    had_error++;
                    continue;
                }
                if (hap >= &addr_ptrs[MAXADDRS - 1]) {
                    if (!toobig++) {
                        debugprintf("Too many addresses (%d)\n", res, MAXADDRS);
                    }
                    cp += n;
                    continue;
                }
                (void) memcpy(*hap++ = bp, cp, (size_t) n);
                bp += n;
                cp += n;
                if (cp != erdata) goto no_recovery;
                break;
            default:
                abort();
        }
        if (!had_error) haveanswer++;
    }
    if (haveanswer) {
        *ap = NULL;
        *hap = NULL;
        /*
         * Note: we sort even if host can take only one address
         * in its return structures - should give it the "best"
         * address in that case, not some random one
         */
        if (res->nsort && haveanswer > 1 && qtype == T_A) addrsort(addr_ptrs, haveanswer, res);
        if (!hent->h_name) {
            n = (int) strlen(qname) + 1; /* for the \0 */
            if (n > ep - bp || n >= MAXHOSTNAMELEN) goto no_recovery;
            strlcpy(bp, qname, (size_t)(ep - bp));
            hent->h_name = bp;
            bp += n;
        }
        if (res->options & RES_USE_INET6) map_v4v6_hostent(hent, &bp, ep);
        if (hent->h_addrtype == AF_INET) pad_v4v6_hostent(hent, &bp, ep);
        goto success;
    }
no_recovery:
    free(aliases);
    *he = NO_RECOVERY;
    return NULL;
success:
    bp = (char*) ALIGN(bp);
    n = (int) (ap - aliases);
    qlen = (n + 1) * sizeof(*hent->h_aliases);
    if ((size_t)(ep - bp) < qlen) goto nospc;
    hent->h_aliases = (char**) bp;
    memcpy(bp, aliases, qlen);
    free(aliases);
    aliases = NULL;

    bp += qlen;
    n = (int) (hap - addr_ptrs);
    qlen = (n + 1) * sizeof(*hent->h_addr_list);
    if ((size_t)(ep - bp) < qlen) goto nospc;
    hent->h_addr_list = (char**) bp;
    memcpy(bp, addr_ptrs, qlen);
    *he = NETDB_SUCCESS;
    return hent;
nospc:
    free(aliases);
    errno = ENOSPC;
    *he = NETDB_INTERNAL;
    return NULL;
}

static int gethostbyname_internal_real(const char* name, int af, res_state res, hostent* hp,
                                       char* buf, size_t buflen, int* he) {
    getnamaddr info;
    size_t size;

    _DIAGASSERT(name != NULL);

    switch (af) {
        case AF_INET:
            size = NS_INADDRSZ;
            break;
        case AF_INET6:
            size = NS_IN6ADDRSZ;
            break;
        default:
            *he = NETDB_INTERNAL;
            errno = EAFNOSUPPORT;
            return EAI_FAMILY;
    }
    if (buflen < size) goto nospc;

    hp->h_addrtype = af;
    hp->h_length = (int) size;

    /*
     * disallow names consisting only of digits/dots, unless
     * they end in a dot.
     */
    if (isdigit((u_char) name[0])) {
        for (const char* cp = name;; ++cp) {
            if (!*cp) {
                if (*--cp == '.') break;
                /*
                 * All-numeric, no dot at the end.
                 * Fake up a hostent as if we'd actually
                 * done a lookup.
                 */
                goto fake;
            }
            if (!isdigit((u_char) *cp) && *cp != '.') break;
        }
    }
    if ((isxdigit((u_char) name[0]) && strchr(name, ':') != NULL) || name[0] == ':') {
        for (const char* cp = name;; ++cp) {
            if (!*cp) {
                if (*--cp == '.') break;
                /*
                 * All-IPv6-legal, no dot at the end.
                 * Fake up a hostent as if we'd actually
                 * done a lookup.
                 */
                goto fake;
            }
            if (!isxdigit((u_char) *cp) && *cp != ':' && *cp != '.') break;
        }
    }

    *he = NETDB_INTERNAL;
    info.hp = hp;
    info.buf = buf;
    info.buflen = buflen;
    info.he = he;
    if (!_hf_gethtbyname2(name, af, &info)) {
        int error = _dns_gethtbyname(name, af, &info);
        if (error != 0) {
            return error;
        }
    }
    *he = NETDB_SUCCESS;
    return 0;
nospc:
    *he = NETDB_INTERNAL;
    errno = ENOSPC;
    // Bad arguments
    return EAI_FAIL;
fake:
    HENT_ARRAY(hp->h_addr_list, 1, buf, buflen);
    HENT_ARRAY(hp->h_aliases, 0, buf, buflen);

    hp->h_aliases[0] = NULL;
    if (size > buflen) goto nospc;

    if (inet_pton(af, name, buf) <= 0) {
        *he = HOST_NOT_FOUND;
        return EAI_NODATA;
    }
    hp->h_addr_list[0] = buf;
    hp->h_addr_list[1] = NULL;
    buf += size;
    buflen -= size;
    HENT_SCOPY(hp->h_name, name, buf, buflen);
    if (res->options & RES_USE_INET6) map_v4v6_hostent(hp, &buf, buf + buflen);
    *he = NETDB_SUCCESS;
    return 0;
}

// very similar in proxy-ness to android_getaddrinfo_proxy
static int gethostbyname_internal(const char* name, int af, res_state res, hostent* hp, char* hbuf,
                                  size_t hbuflen, int* errorp,
                                  const android_net_context* netcontext) {
    res_setnetcontext(res, netcontext);
    return gethostbyname_internal_real(name, af, res, hp, hbuf, hbuflen, errorp);
}

static struct hostent* android_gethostbyaddrfornetcontext_real(
        const void* addr, socklen_t len, int af, struct hostent* hp, char* buf, size_t buflen,
        int* he, const struct android_net_context* netcontext) {
    const u_char* uaddr = (const u_char*) addr;
    socklen_t size;
    struct getnamaddr info;

    _DIAGASSERT(addr != NULL);

    if (af == AF_INET6 && len == NS_IN6ADDRSZ &&
        (IN6_IS_ADDR_LINKLOCAL((const struct in6_addr*) addr) ||
         IN6_IS_ADDR_SITELOCAL((const struct in6_addr*) addr))) {
        *he = HOST_NOT_FOUND;
        return NULL;
    }
    if (af == AF_INET6 && len == NS_IN6ADDRSZ &&
        (IN6_IS_ADDR_V4MAPPED((const struct in6_addr*) addr) ||
         IN6_IS_ADDR_V4COMPAT((const struct in6_addr*) addr))) {
        /* Unmap. */
        uaddr += NS_IN6ADDRSZ - NS_INADDRSZ;
        addr = uaddr;
        af = AF_INET;
        len = NS_INADDRSZ;
    }
    switch (af) {
        case AF_INET:
            size = NS_INADDRSZ;
            break;
        case AF_INET6:
            size = NS_IN6ADDRSZ;
            break;
        default:
            errno = EAFNOSUPPORT;
            *he = NETDB_INTERNAL;
            return NULL;
    }
    if (size != len) {
        errno = EINVAL;
        *he = NETDB_INTERNAL;
        return NULL;
    }
    info.hp = hp;
    info.buf = buf;
    info.buflen = buflen;
    info.he = he;
    *he = NETDB_INTERNAL;
    if (!_hf_gethtbyaddr(uaddr, len, af, &info)) {
        if (!_dns_gethtbyaddr(uaddr, len, af, netcontext, &info)) {
            return NULL;
        }
    }
    *he = NETDB_SUCCESS;
    return hp;
}

static struct hostent* android_gethostbyaddrfornetcontext_proxy_internal(
        const void* addr, socklen_t len, int af, struct hostent* hp, char* hbuf, size_t hbuflen,
        int* he, const struct android_net_context* netcontext) {
    return android_gethostbyaddrfornetcontext_real(addr, len, af, hp, hbuf, hbuflen, he,
                                                   netcontext);
}

struct hostent* netbsd_gethostent_r(FILE* hf, struct hostent* hent, char* buf, size_t buflen,
                                    int* he) {
    const size_t line_buf_size = sizeof(res_get_static()->hostbuf);
    char *name;
    char *cp, **q;
    int af, len;
    size_t anum;
    struct in6_addr host_addr;

    if (hf == NULL) {
        *he = NETDB_INTERNAL;
        errno = EINVAL;
        return NULL;
    }
    char* p = NULL;
    size_t maxaliases = 10;
    char** aliases = (char**) malloc(maxaliases * sizeof(char*));
    if (!aliases) goto nospc;

    /* Allocate a new space to read file lines like upstream does.
     * To keep reentrancy we cannot use res_get_static()->hostbuf here,
     * as the buffer may be used to store content for a previous hostent
     * returned by non-reentrant functions like gethostbyname().
     */
    if ((p = (char*) malloc(line_buf_size)) == NULL) {
        goto nospc;
    }
    for (;;) {
        if (!fgets(p, line_buf_size, hf)) {
            free(p);
            free(aliases);
            *he = HOST_NOT_FOUND;
            return NULL;
        }
        if (*p == '#') {
            continue;
        }
        if (!(cp = strpbrk(p, "#\n"))) {
            continue;
        }
        *cp = '\0';
        if (!(cp = strpbrk(p, " \t"))) continue;
        *cp++ = '\0';
        if (inet_pton(AF_INET6, p, &host_addr) > 0) {
            af = AF_INET6;
            len = NS_IN6ADDRSZ;
        } else {
            if (inet_pton(AF_INET, p, &host_addr) <= 0) continue;

            res_state res = res_get_state();
            if (res == NULL) goto nospc;
            if (res->options & RES_USE_INET6) {
                map_v4v6_address(buf, buf);
                af = AF_INET6;
                len = NS_IN6ADDRSZ;
            } else {
                af = AF_INET;
                len = NS_INADDRSZ;
            }
        }

        /* if this is not something we're looking for, skip it. */
        if (hent->h_addrtype != 0 && hent->h_addrtype != af) continue;
        if (hent->h_length != 0 && hent->h_length != len) continue;

        while (*cp == ' ' || *cp == '\t') cp++;
        if ((cp = strpbrk(name = cp, " \t")) != NULL) *cp++ = '\0';
        q = aliases;
        while (cp && *cp) {
            if (*cp == ' ' || *cp == '\t') {
                cp++;
                continue;
            }
            addalias(q, cp, aliases, maxaliases);
            if ((cp = strpbrk(cp, " \t")) != NULL) *cp++ = '\0';
        }
        break;
    }
    hent->h_length = len;
    hent->h_addrtype = af;
    HENT_ARRAY(hent->h_addr_list, 1, buf, buflen);
    anum = (size_t)(q - aliases);
    HENT_ARRAY(hent->h_aliases, anum, buf, buflen);
    HENT_COPY(hent->h_addr_list[0], &host_addr, hent->h_length, buf, buflen);
    hent->h_addr_list[1] = NULL;

    /* Reserve space for mapping IPv4 address to IPv6 address in place */
    if (hent->h_addrtype == AF_INET) {
        HENT_COPY(buf, NAT64_PAD, sizeof(NAT64_PAD), buf, buflen);
    }

    HENT_SCOPY(hent->h_name, name, buf, buflen);
    for (size_t i = 0; i < anum; i++) HENT_SCOPY(hent->h_aliases[i], aliases[i], buf, buflen);
    hent->h_aliases[anum] = NULL;

    *he = NETDB_SUCCESS;
    free(p);
    free(aliases);
    return hent;
nospc:
    free(p);
    free(aliases);
    errno = ENOSPC;
    *he = NETDB_INTERNAL;
    return NULL;
}

static void map_v4v6_address(const char* src, char* dst) {
    u_char* p = (u_char*) dst;
    char tmp[NS_INADDRSZ];
    int i;

    _DIAGASSERT(src != NULL);
    _DIAGASSERT(dst != NULL);

    /* Stash a temporary copy so our caller can update in place. */
    memcpy(tmp, src, NS_INADDRSZ);
    /* Mark this ipv6 addr as a mapped ipv4. */
    for (i = 0; i < 10; i++) *p++ = 0x00;
    *p++ = 0xff;
    *p++ = 0xff;
    /* Retrieve the saved copy and we're done. */
    memcpy(p, tmp, NS_INADDRSZ);
}

static void convert_v4v6_hostent(struct hostent* hp, char** bpp, char* ep,
                                 std::function<void(struct hostent* hp)> map_param,
                                 std::function<void(char* src, char* dst)> map_addr) {
    _DIAGASSERT(hp != NULL);
    _DIAGASSERT(bpp != NULL);
    _DIAGASSERT(ep != NULL);

    if (hp->h_addrtype != AF_INET || hp->h_length != NS_INADDRSZ) return;
    map_param(hp);
    for (char** ap = hp->h_addr_list; *ap; ap++) {
        int i = (int) (sizeof(align) - (size_t)((u_long) *bpp % sizeof(align)));

        if (ep - *bpp < (i + NS_IN6ADDRSZ)) {
            /* Out of memory.  Truncate address list here.  XXX */
            *ap = NULL;
            return;
        }
        *bpp += i;
        map_addr(*ap, *bpp);
        *ap = *bpp;
        *bpp += NS_IN6ADDRSZ;
    }
}

static void map_v4v6_hostent(struct hostent* hp, char** bpp, char* ep) {
    convert_v4v6_hostent(hp, bpp, ep,
                         [](struct hostent* hp) {
                             hp->h_addrtype = AF_INET6;
                             hp->h_length = NS_IN6ADDRSZ;
                         },
                         [](char* src, char* dst) { map_v4v6_address(src, dst); });
}

/* Reserve space for mapping IPv4 address to IPv6 address in place */
static void pad_v4v6_hostent(struct hostent* hp, char** bpp, char* ep) {
    convert_v4v6_hostent(hp, bpp, ep,
                         [](struct hostent* hp) {
                             (void) hp; /* unused */
                         },
                         [](char* src, char* dst) {
                             memcpy(dst, src, NS_INADDRSZ);
                             memcpy(dst + NS_INADDRSZ, NAT64_PAD, sizeof(NAT64_PAD));
                         });
}

static void addrsort(char** ap, int num, res_state res) {
    int i, j;
    char** p;
    short aval[MAXADDRS];
    int needsort = 0;

    _DIAGASSERT(ap != NULL);

    p = ap;
    for (i = 0; i < num; i++, p++) {
        for (j = 0; (unsigned) j < res->nsort; j++)
            if (res->sort_list[j].addr.s_addr ==
                (((struct in_addr*) (void*) (*p))->s_addr & res->sort_list[j].mask))
                break;
        aval[i] = j;
        if (needsort == 0 && i > 0 && j < aval[i - 1]) needsort = i;
    }
    if (!needsort) return;

    while (needsort < num) {
        for (j = needsort - 1; j >= 0; j--) {
            if (aval[j] > aval[j + 1]) {
                char* hp;

                i = aval[j];
                aval[j] = aval[j + 1];
                aval[j + 1] = i;

                hp = ap[j];
                ap[j] = ap[j + 1];
                ap[j + 1] = hp;
            } else
                break;
        }
        needsort++;
    }
}

static int _dns_gethtbyname(const char* name, int addr_type, getnamaddr* info) {
    int n, type;
    struct hostent* hp;
    res_state res;

    info->hp->h_addrtype = addr_type;

    switch (info->hp->h_addrtype) {
        case AF_INET:
            info->hp->h_length = NS_INADDRSZ;
            type = T_A;
            break;
        case AF_INET6:
            info->hp->h_length = NS_IN6ADDRSZ;
            type = T_AAAA;
            break;
        default:
            return EAI_FAMILY;
    }
    querybuf* buf = (querybuf*) malloc(sizeof(querybuf));
    if (buf == NULL) {
        *info->he = NETDB_INTERNAL;
        return EAI_MEMORY;
    }
    res = res_get_state();
    if (res == NULL) {
        free(buf);
        return EAI_MEMORY;
    }

    int ai_error = EAI_NODATA;
    n = res_nsearch(res, name, C_IN, type, buf->buf, (int) sizeof(buf->buf), &ai_error);
    if (n < 0) {
        free(buf);
        debugprintf("res_nsearch failed (%d)\n", res, n);

        // If server responds empty answer with rcode NOERROR, adjust the error so netd will
        // get the nulltpr hp.
        // TODO: Adjust the error closed to res_nsend instead of here after h_errno is removed.
        if (ai_error == 0) {
            return herrnoToAiError(h_errno);
        }
        return ai_error;
    }
    hp = getanswer(buf, n, name, type, res, info->hp, info->buf, info->buflen, info->he);
    free(buf);
    if (hp == NULL) {
        return herrnoToAiError(h_errno);
    }
    return 0;
}

static bool _dns_gethtbyaddr(const unsigned char* uaddr, int len, int af,
                             const android_net_context* netcontext, getnamaddr* info) {
    char qbuf[MAXDNAME + 1], *qp, *ep;
    int n;
    struct hostent* hp;
    int advance;
    res_state res;

    info->hp->h_length = len;
    info->hp->h_addrtype = af;

    switch (info->hp->h_addrtype) {
        case AF_INET:
            (void) snprintf(qbuf, sizeof(qbuf), "%u.%u.%u.%u.in-addr.arpa", (uaddr[3] & 0xff),
                            (uaddr[2] & 0xff), (uaddr[1] & 0xff), (uaddr[0] & 0xff));
            break;

        case AF_INET6:
            qp = qbuf;
            ep = qbuf + sizeof(qbuf) - 1;
            for (n = NS_IN6ADDRSZ - 1; n >= 0; n--) {
                advance = snprintf(qp, (size_t)(ep - qp), "%x.%x.", uaddr[n] & 0xf,
                                   ((unsigned int) uaddr[n] >> 4) & 0xf);
                if (advance > 0 && qp + advance < ep)
                    qp += advance;
                else {
                    *info->he = NETDB_INTERNAL;
                    return false;
                }
            }
            if (strlcat(qbuf, "ip6.arpa", sizeof(qbuf)) >= sizeof(qbuf)) {
                *info->he = NETDB_INTERNAL;
                return false;
            }
            break;
        default:
            return false;
    }

    querybuf* buf = (querybuf*) malloc(sizeof(querybuf));
    if (buf == NULL) {
        *info->he = NETDB_INTERNAL;
        return false;
    }
    res = res_get_state();
    if (res == NULL) {
        free(buf);
        return false;
    }
    res_setnetcontext(res, netcontext);
    int ai_error = 0;
    n = res_nquery(res, qbuf, C_IN, T_PTR, buf->buf, (int) sizeof(buf->buf), &ai_error);
    if (n < 0) {
        free(buf);
        debugprintf("res_nquery failed (%d)\n", res, n);
        return false;
    }
    hp = getanswer(buf, n, qbuf, T_PTR, res, info->hp, info->buf, info->buflen, info->he);
    free(buf);
    if (hp == NULL) {
        return false;
    }

    char* bf = (char*) (hp->h_addr_list + 2);
    size_t blen = (size_t)(bf - info->buf);
    if (blen + info->hp->h_length > info->buflen) goto nospc;
    hp->h_addr_list[0] = bf;
    hp->h_addr_list[1] = NULL;
    memcpy(bf, uaddr, (size_t) info->hp->h_length);
    if (info->hp->h_addrtype == AF_INET && (res->options & RES_USE_INET6)) {
        if (blen + NS_IN6ADDRSZ > info->buflen) goto nospc;
        map_v4v6_address(bf, bf);
        hp->h_addrtype = AF_INET6;
        hp->h_length = NS_IN6ADDRSZ;
    }

    /* Reserve enough space for mapping IPv4 address to IPv6 address in place */
    if (info->hp->h_addrtype == AF_INET) {
        if (blen + NS_IN6ADDRSZ > info->buflen) goto nospc;
        // Pad zero to the unused address space
        memcpy(bf + NS_INADDRSZ, NAT64_PAD, sizeof(NAT64_PAD));
    }

    *info->he = NETDB_SUCCESS;
    return true;

nospc:
    errno = ENOSPC;
    *info->he = NETDB_INTERNAL;
    return false;
}

/*
 * Non-reentrant versions.
 */

int android_gethostbynamefornetcontext(const char* name, int af,
                                       const struct android_net_context* netcontext, hostent** hp) {
    int error;
    res_state res = res_get_state();
    if (res == NULL) return EAI_MEMORY;
    res_static* rs = res_get_static();  // For thread-safety.
    error = gethostbyname_internal(name, af, res, &rs->host, rs->hostbuf, sizeof(rs->hostbuf),
                                   &h_errno, netcontext);
    if (error == 0) {
        *hp = &rs->host;
    }
    return error;
}

struct hostent* android_gethostbyaddrfornetcontext(const void* addr, socklen_t len, int af,
                                                   const struct android_net_context* netcontext) {
    return android_gethostbyaddrfornetcontext_proxy(addr, len, af, netcontext);
}

static struct hostent* android_gethostbyaddrfornetcontext_proxy(
        const void* addr, socklen_t len, int af, const struct android_net_context* netcontext) {
    struct res_static* rs = res_get_static();  // For thread-safety.
    return android_gethostbyaddrfornetcontext_proxy_internal(
            addr, len, af, &rs->host, rs->hostbuf, sizeof(rs->hostbuf), &h_errno, netcontext);
}

int herrnoToAiError(int herror) {
    switch (herror) {
        case HOST_NOT_FOUND:
            return EAI_NODATA;
        case TRY_AGAIN:
            return EAI_AGAIN;
        default:
            return EAI_FAIL;
    }
}

int rcodeToAiError(int rcode) {
    // Catch the two cases (success, timeout). For other cases, just set it EAI_NODATA
    // as EAI_NODATA is returned in dns_getaddrinfo() when res_searchN() returns -1.
    switch (rcode) {
        case NOERROR:
            return 0;
        case RCODE_TIMEOUT:
            return NETD_RESOLV_TIMEOUT;
        default:
            return EAI_NODATA;
    }
}
