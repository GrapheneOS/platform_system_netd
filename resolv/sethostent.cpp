/*	$NetBSD: sethostent.c,v 1.20 2014/03/17 13:24:23 christos Exp $	*/

/*
 * Copyright (c) 1985, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 */

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <nsswitch.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include "hostent.h"
#include "resolv_private.h"

// NetBSD uses _DIAGASSERT to null-check arguments and the like,
// but it's clear from the number of mistakes in their assertions
// that they don't actually test or ship with this.
#define _DIAGASSERT(e) /* nothing */

#define ALIGNBYTES (sizeof(uintptr_t) - 1)
#define ALIGN(p) (((uintptr_t)(p) + ALIGNBYTES) & ~ALIGNBYTES)

static void sethostent_r(FILE** hf) {
    if (!*hf)
        *hf = fopen(_PATH_HOSTS, "re");
    else
        rewind(*hf);
}

static void endhostent_r(FILE** hf) {
    if (*hf) {
        (void) fclose(*hf);
        *hf = NULL;
    }
}

hostent* _hf_gethtbyname2(const char* name, int af, getnamaddr* info) {
    struct hostent *hp, hent;
    char *buf, *ptr;
    size_t len, anum, num, i;
    FILE* hf;
    char* aliases[MAXALIASES];
    char* addr_ptrs[MAXADDRS];

    _DIAGASSERT(name != NULL);

    hf = NULL;
    sethostent_r(&hf);
    if (hf == NULL) {
        errno = EINVAL;
        *info->he = NETDB_INTERNAL;
        return NULL;
    }

    if ((ptr = buf = (char*) malloc(len = info->buflen)) == NULL) {
        *info->he = NETDB_INTERNAL;
        return NULL;
    }

    anum = 0;            /* XXX: gcc */
    hent.h_name = NULL;  /* XXX: gcc */
    hent.h_addrtype = 0; /* XXX: gcc */
    hent.h_length = 0;   /* XXX: gcc */

    for (num = 0; num < MAXADDRS;) {
        info->hp->h_addrtype = af;
        info->hp->h_length = 0;

        hp = netbsd_gethostent_r(hf, info->hp, info->buf, info->buflen, info->he);
        if (hp == NULL) {
            if (*info->he == NETDB_INTERNAL && errno == ENOSPC) {
                goto nospc;  // glibc compatibility.
            }
            break;
        }

        if (strcasecmp(hp->h_name, name) != 0) {
            char** cp;
            for (cp = hp->h_aliases; *cp != NULL; cp++)
                if (strcasecmp(*cp, name) == 0) break;
            if (*cp == NULL) continue;
        }

        if (num == 0) {
            hent.h_addrtype = hp->h_addrtype;
            hent.h_length = hp->h_length;

            HENT_SCOPY(hent.h_name, hp->h_name, ptr, len);
            for (anum = 0; hp->h_aliases[anum]; anum++) {
                if (anum >= MAXALIASES) goto nospc;
                HENT_SCOPY(aliases[anum], hp->h_aliases[anum], ptr, len);
            }
            ptr = (char*) ALIGN(ptr);
            if ((size_t)(ptr - buf) >= info->buflen) goto nospc;
        }

        if (num >= MAXADDRS) goto nospc;
        HENT_COPY(addr_ptrs[num], hp->h_addr_list[0], hp->h_length, ptr, len);
        num++;
    }
    endhostent_r(&hf);

    if (num == 0) {
        *info->he = HOST_NOT_FOUND;
        free(buf);
        return NULL;
    }

    hp = info->hp;
    ptr = info->buf;
    len = info->buflen;

    hp->h_addrtype = hent.h_addrtype;
    hp->h_length = hent.h_length;

    HENT_ARRAY(hp->h_aliases, anum, ptr, len);
    HENT_ARRAY(hp->h_addr_list, num, ptr, len);

    for (i = 0; i < num; i++) HENT_COPY(hp->h_addr_list[i], addr_ptrs[i], hp->h_length, ptr, len);
    hp->h_addr_list[num] = NULL;

    HENT_SCOPY(hp->h_name, hent.h_name, ptr, len);

    for (i = 0; i < anum; i++) HENT_SCOPY(hp->h_aliases[i], aliases[i], ptr, len);
    hp->h_aliases[anum] = NULL;

    free(buf);
    return hp;
nospc:
    *info->he = NETDB_INTERNAL;
    free(buf);
    errno = ENOSPC;
    return NULL;
}

int _hf_gethtbyaddr(void* rv, void* /*cb_data*/, va_list ap) {
    struct hostent* hp;
    const unsigned char* addr;
    struct getnamaddr* info = (struct getnamaddr*) rv;
    FILE* hf;

    _DIAGASSERT(rv != NULL);

    addr = va_arg(ap, unsigned char*);
    info->hp->h_length = va_arg(ap, int);
    info->hp->h_addrtype = va_arg(ap, int);

    hf = NULL;
    sethostent_r(&hf);
    if (hf == NULL) {
        *info->he = NETDB_INTERNAL;
        return NS_UNAVAIL;
    }
    while ((hp = netbsd_gethostent_r(hf, info->hp, info->buf, info->buflen, info->he)) != NULL)
        if (!memcmp(hp->h_addr_list[0], addr, (size_t) hp->h_length)) break;
    endhostent_r(&hf);

    if (hp == NULL) {
        if (errno == ENOSPC) return NS_UNAVAIL;  // glibc compatibility.
        *info->he = HOST_NOT_FOUND;
        return NS_NOTFOUND;
    }
    return NS_SUCCESS;
}
