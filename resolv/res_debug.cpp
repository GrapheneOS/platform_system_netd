/*	$NetBSD: res_debug.c,v 1.13 2012/06/25 22:32:45 abs Exp $	*/

/*
 * Portions Copyright (C) 2004, 2005, 2008, 2009  Internet Systems Consortium, Inc. ("ISC")
 * Portions Copyright (C) 1996-2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright (c) 1985
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
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "resolv_private.h"

struct res_sym {
    int number;            /* Identifying number, like T_MX */
    const char* name;      /* Its symbolic name, like "MX" */
    const char* humanname; /* Its fun name, like "mail exchanger" */
};

static void do_section(const res_state statp, ns_msg* handle, ns_sect section, int pflag,
                       FILE* file) {
    int n, sflag, rrnum;
    int buflen = 2048;
    ns_opcode opcode;
    ns_rr rr;

    /*
     * Print answer records.
     */
    sflag = (int) (statp->pfcode & pflag);
    if (statp->pfcode && !sflag) return;

    char* buf = (char*) malloc((size_t) buflen);
    if (buf == NULL) {
        fprintf(file, ";; memory allocation failure\n");
        return;
    }

    opcode = (ns_opcode) ns_msg_getflag(*handle, ns_f_opcode);
    rrnum = 0;
    for (;;) {
        if (ns_parserr(handle, section, rrnum, &rr)) {
            if (errno != ENODEV)
                fprintf(file, ";; ns_parserr: %s\n", strerror(errno));
            else if (rrnum > 0 && sflag != 0 && (statp->pfcode & RES_PRF_HEAD1))
                putc('\n', file);
            goto cleanup;
        }
        if (rrnum == 0 && sflag != 0 && (statp->pfcode & RES_PRF_HEAD1))
            fprintf(file, ";; %s SECTION:\n", p_section(section, opcode));
        if (section == ns_s_qd)
            fprintf(file, ";;\t%s, type = %s, class = %s\n", ns_rr_name(rr), p_type(ns_rr_type(rr)),
                    p_class(ns_rr_class(rr)));
        else if (section == ns_s_ar && ns_rr_type(rr) == ns_t_opt) {
            size_t rdatalen, ttl;
            uint16_t optcode, optlen;

            rdatalen = ns_rr_rdlen(rr);
            ttl = ns_rr_ttl(rr);
            fprintf(file, "; EDNS: version: %zu, udp=%u, flags=%04zx\n", (ttl >> 16) & 0xff,
                    ns_rr_class(rr), ttl & 0xffff);
            while (rdatalen >= 4) {
                const u_char* cp = ns_rr_rdata(rr);
                int i;

                GETSHORT(optcode, cp);
                GETSHORT(optlen, cp);

                if (optcode == NS_OPT_NSID) {
                    fputs("; NSID: ", file);
                    if (optlen == 0) {
                        fputs("; NSID\n", file);
                    } else {
                        fputs("; NSID: ", file);
                        for (i = 0; i < optlen; i++) fprintf(file, "%02x ", cp[i]);
                        fputs(" (", file);
                        for (i = 0; i < optlen; i++)
                            fprintf(file, "%c", isprint(cp[i]) ? cp[i] : '.');
                        fputs(")\n", file);
                    }
                } else {
                    if (optlen == 0) {
                        fprintf(file, "; OPT=%u\n", optcode);
                    } else {
                        fprintf(file, "; OPT=%u: ", optcode);
                        for (i = 0; i < optlen; i++) fprintf(file, "%02x ", cp[i]);
                        fputs(" (", file);
                        for (i = 0; i < optlen; i++)
                            fprintf(file, "%c", isprint(cp[i]) ? cp[i] : '.');
                        fputs(")\n", file);
                    }
                }
                rdatalen -= 4 + optlen;
            }
        } else {
            n = ns_sprintrr(handle, &rr, NULL, NULL, buf, (u_int) buflen);
            if (n < 0) {
                if (errno == ENOSPC) {
                    free(buf);
                    buf = NULL;
                    if (buflen < 131072) {
                        buf = (char*) malloc((size_t)(buflen += 1024));
                    }
                    if (buf == NULL) {
                        fprintf(file, ";; memory allocation failure\n");
                        return;
                    }
                    continue;
                }
                fprintf(file, ";; ns_sprintrr: %s\n", strerror(errno));
                goto cleanup;
            }
            fputs(buf, file);
            fputc('\n', file);
        }
        rrnum++;
    }
cleanup:
    free(buf);
}

/*
 * Print the contents of a query.
 * This is intended to be primarily a debugging routine.
 */
void res_pquery(const res_state statp, const u_char* msg, int len, FILE* file) {
    ns_msg handle;
    int qdcount, ancount, nscount, arcount;
    u_int opcode, rcode, id;

    if (ns_initparse(msg, len, &handle) < 0) {
        fprintf(file, ";; ns_initparse: %s\n", strerror(errno));
        return;
    }
    opcode = ns_msg_getflag(handle, ns_f_opcode);
    rcode = ns_msg_getflag(handle, ns_f_rcode);
    id = ns_msg_id(handle);
    qdcount = ns_msg_count(handle, ns_s_qd);
    ancount = ns_msg_count(handle, ns_s_an);
    nscount = ns_msg_count(handle, ns_s_ns);
    arcount = ns_msg_count(handle, ns_s_ar);

    /*
     * Print header fields.
     */
    if ((!statp->pfcode) || (statp->pfcode & RES_PRF_HEADX) || rcode)
        fprintf(file, ";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n", _res_opcodes[opcode],
                p_rcode((int) rcode), id);
    if ((!statp->pfcode) || (statp->pfcode & RES_PRF_HEADX)) putc(';', file);
    if ((!statp->pfcode) || (statp->pfcode & RES_PRF_HEAD2)) {
        fprintf(file, "; flags:");
        if (ns_msg_getflag(handle, ns_f_qr)) fprintf(file, " qr");
        if (ns_msg_getflag(handle, ns_f_aa)) fprintf(file, " aa");
        if (ns_msg_getflag(handle, ns_f_tc)) fprintf(file, " tc");
        if (ns_msg_getflag(handle, ns_f_rd)) fprintf(file, " rd");
        if (ns_msg_getflag(handle, ns_f_ra)) fprintf(file, " ra");
        if (ns_msg_getflag(handle, ns_f_z)) fprintf(file, " ??");
        if (ns_msg_getflag(handle, ns_f_ad)) fprintf(file, " ad");
        if (ns_msg_getflag(handle, ns_f_cd)) fprintf(file, " cd");
    }
    if ((!statp->pfcode) || (statp->pfcode & RES_PRF_HEAD1)) {
        fprintf(file, "; %s: %d", p_section(ns_s_qd, (int) opcode), qdcount);
        fprintf(file, ", %s: %d", p_section(ns_s_an, (int) opcode), ancount);
        fprintf(file, ", %s: %d", p_section(ns_s_ns, (int) opcode), nscount);
        fprintf(file, ", %s: %d", p_section(ns_s_ar, (int) opcode), arcount);
    }
    if ((!statp->pfcode) || (statp->pfcode & (RES_PRF_HEADX | RES_PRF_HEAD2 | RES_PRF_HEAD1))) {
        putc('\n', file);
    }
    /*
     * Print the various sections.
     */
    do_section(statp, &handle, ns_s_qd, RES_PRF_QUES, file);
    do_section(statp, &handle, ns_s_an, RES_PRF_ANS, file);
    do_section(statp, &handle, ns_s_ns, RES_PRF_AUTH, file);
    do_section(statp, &handle, ns_s_ar, RES_PRF_ADD, file);
    if (qdcount == 0 && ancount == 0 && nscount == 0 && arcount == 0) putc('\n', file);
}

const u_char* p_cdnname(const u_char* cp, const u_char* msg, int len, FILE* file) {
    char name[MAXDNAME];
    int n;

    if ((n = dn_expand(msg, msg + len, cp, name, (int) sizeof name)) < 0) return (NULL);
    if (name[0] == '\0')
        putc('.', file);
    else
        fputs(name, file);
    return (cp + n);
}

const u_char* p_cdname(const u_char* cp, const u_char* msg, FILE* file) {
    return (p_cdnname(cp, msg, PACKETSZ, file));
}

/* Return a fully-qualified domain name from a compressed name (with
   length supplied).  */

const u_char* p_fqnname(const u_char* cp, const u_char* msg, int msglen, char* name, int namelen) {
    int n;
    size_t newlen;

    if ((n = dn_expand(msg, cp + msglen, cp, name, namelen)) < 0) return (NULL);
    newlen = strlen(name);
    if (newlen == 0 || name[newlen - 1] != '.') {
        if ((int) newlen + 1 >= namelen) /* Lack space for final dot */
            return (NULL);
        else
            strcpy(name + newlen, ".");
    }
    return (cp + n);
}

/* XXX:	the rest of these functions need to become length-limited, too. */

const u_char* p_fqname(const u_char* cp, const u_char* msg, FILE* file) {
    char name[MAXDNAME];
    const u_char* n;

    n = p_fqnname(cp, msg, MAXCDNAME, name, (int) sizeof name);
    if (n == NULL) return (NULL);
    fputs(name, file);
    return (n);
}

/*
 * Names of RR classes and qclasses.  Classes and qclasses are the same, except
 * that C_ANY is a qclass but not a class.  (You can ask for records of class
 * C_ANY, but you can't have any records of that class in the database.)
 */
static const struct res_sym p_class_syms[] = {
        {C_IN, "IN", (char*) 0},     {C_CHAOS, "CH", (char*) 0},  {C_CHAOS, "CHAOS", (char*) 0},
        {C_HS, "HS", (char*) 0},     {C_HS, "HESIOD", (char*) 0}, {C_ANY, "ANY", (char*) 0},
        {C_NONE, "NONE", (char*) 0}, {C_IN, (char*) 0, (char*) 0}};

/*
 * Names of message sections.
 */
static const struct res_sym p_default_section_syms[] = {{ns_s_qd, "QUERY", (char*) 0},
                                                        {ns_s_an, "ANSWER", (char*) 0},
                                                        {ns_s_ns, "AUTHORITY", (char*) 0},
                                                        {ns_s_ar, "ADDITIONAL", (char*) 0},
                                                        {0, (char*) 0, (char*) 0}};

static const struct res_sym p_update_section_syms[] = {{S_ZONE, "ZONE", (char*) 0},
                                                       {S_PREREQ, "PREREQUISITE", (char*) 0},
                                                       {S_UPDATE, "UPDATE", (char*) 0},
                                                       {S_ADDT, "ADDITIONAL", (char*) 0},
                                                       {0, (char*) 0, (char*) 0}};

/*
 * Names of RR types and qtypes.  Types and qtypes are the same, except
 * that T_ANY is a qtype but not a type.  (You can ask for records of type
 * T_ANY, but you can't have any records of that type in the database.)
 */
const struct res_sym p_type_syms[] = {
        {ns_t_a, "A", "address"},
        {ns_t_ns, "NS", "name server"},
        {ns_t_md, "MD", "mail destination (deprecated)"},
        {ns_t_mf, "MF", "mail forwarder (deprecated)"},
        {ns_t_cname, "CNAME", "canonical name"},
        {ns_t_soa, "SOA", "start of authority"},
        {ns_t_mb, "MB", "mailbox"},
        {ns_t_mg, "MG", "mail group member"},
        {ns_t_mr, "MR", "mail rename"},
        {ns_t_null, "NULL", "null"},
        {ns_t_wks, "WKS", "well-known service (deprecated)"},
        {ns_t_ptr, "PTR", "domain name pointer"},
        {ns_t_hinfo, "HINFO", "host information"},
        {ns_t_minfo, "MINFO", "mailbox information"},
        {ns_t_mx, "MX", "mail exchanger"},
        {ns_t_txt, "TXT", "text"},
        {ns_t_rp, "RP", "responsible person"},
        {ns_t_afsdb, "AFSDB", "DCE or AFS server"},
        {ns_t_x25, "X25", "X25 address"},
        {ns_t_isdn, "ISDN", "ISDN address"},
        {ns_t_rt, "RT", "router"},
        {ns_t_nsap, "NSAP", "nsap address"},
        {ns_t_nsap_ptr, "NSAP_PTR", "domain name pointer"},
        {ns_t_sig, "SIG", "signature"},
        {ns_t_key, "KEY", "key"},
        {ns_t_px, "PX", "mapping information"},
        {ns_t_gpos, "GPOS", "geographical position (withdrawn)"},
        {ns_t_aaaa, "AAAA", "IPv6 address"},
        {ns_t_loc, "LOC", "location"},
        {ns_t_nxt, "NXT", "next valid name (unimplemented)"},
        {ns_t_eid, "EID", "endpoint identifier (unimplemented)"},
        {ns_t_nimloc, "NIMLOC", "NIMROD locator (unimplemented)"},
        {ns_t_srv, "SRV", "server selection"},
        {ns_t_atma, "ATMA", "ATM address (unimplemented)"},
        {ns_t_naptr, "NAPTR", "naptr"},
        {ns_t_kx, "KX", "key exchange"},
        {ns_t_cert, "CERT", "certificate"},
        {ns_t_a6, "A", "IPv6 address (experminental)"},
        {ns_t_dname, "DNAME", "non-terminal redirection"},
        {ns_t_opt, "OPT", "opt"},
        {ns_t_apl, "apl", "apl"},
        {ns_t_ds, "DS", "delegation signer"},
        {ns_t_sshfp, "SSFP", "SSH fingerprint"},
        {ns_t_ipseckey, "IPSECKEY", "IPSEC key"},
        {ns_t_rrsig, "RRSIG", "rrsig"},
        {ns_t_nsec, "NSEC", "nsec"},
        {ns_t_dnskey, "DNSKEY", "DNS key"},
        {ns_t_dhcid, "DHCID", "dynamic host configuration identifier"},
        {ns_t_nsec3, "NSEC3", "nsec3"},
        {ns_t_nsec3param, "NSEC3PARAM", "NSEC3 parameters"},
        {ns_t_hip, "HIP", "host identity protocol"},
        {ns_t_spf, "SPF", "sender policy framework"},
        {ns_t_tkey, "TKEY", "tkey"},
        {ns_t_tsig, "TSIG", "transaction signature"},
        {ns_t_ixfr, "IXFR", "incremental zone transfer"},
        {ns_t_axfr, "AXFR", "zone transfer"},
        {ns_t_zxfr, "ZXFR", "compressed zone transfer"},
        {ns_t_mailb, "MAILB", "mailbox-related data (deprecated)"},
        {ns_t_maila, "MAILA", "mail agent (deprecated)"},
        {ns_t_naptr, "NAPTR", "URN Naming Authority"},
        {ns_t_kx, "KX", "Key Exchange"},
        {ns_t_cert, "CERT", "Certificate"},
        {ns_t_a6, "A6", "IPv6 Address"},
        {ns_t_dname, "DNAME", "dname"},
        {ns_t_sink, "SINK", "Kitchen Sink (experimental)"},
        {ns_t_opt, "OPT", "EDNS Options"},
        {ns_t_any, "ANY", "\"any\""},
        {ns_t_dlv, "DLV", "DNSSEC look-aside validation"},
        {0, NULL, NULL}};

/*
 * Names of DNS rcodes.
 */
static const struct res_sym p_rcode_syms[] = {{ns_r_noerror, "NOERROR", "no error"},
                                              {ns_r_formerr, "FORMERR", "format error"},
                                              {ns_r_servfail, "SERVFAIL", "server failed"},
                                              {ns_r_nxdomain, "NXDOMAIN", "no such domain name"},
                                              {ns_r_notimpl, "NOTIMP", "not implemented"},
                                              {ns_r_refused, "REFUSED", "refused"},
                                              {ns_r_yxdomain, "YXDOMAIN", "domain name exists"},
                                              {ns_r_yxrrset, "YXRRSET", "rrset exists"},
                                              {ns_r_nxrrset, "NXRRSET", "rrset doesn't exist"},
                                              {ns_r_notauth, "NOTAUTH", "not authoritative"},
                                              {ns_r_notzone, "NOTZONE", "Not in zone"},
                                              {ns_r_max, "", ""},
                                              {ns_r_badsig, "BADSIG", "bad signature"},
                                              {ns_r_badkey, "BADKEY", "bad key"},
                                              {ns_r_badtime, "BADTIME", "bad time"},
                                              {0, NULL, NULL}};

static const char* sym_ntos(const struct res_sym* syms, int number, int* success) {
    static char unname[20];

    for (; syms->name != 0; syms++) {
        if (number == syms->number) {
            if (success) *success = 1;
            return (syms->name);
        }
    }

    snprintf(unname, sizeof(unname), "%d", number); /* XXX nonreentrant */
    if (success) *success = 0;
    return (unname);
}

/*
 * Return a string for the type.
 */
const char* p_type(int type) {
    int success;
    const char* result;
    static char typebuf[20];

    result = sym_ntos(p_type_syms, type, &success);
    if (success) return (result);
    if (type < 0 || type > 0xffff) return ("BADTYPE");
    snprintf(typebuf, sizeof(typebuf), "TYPE%d", type);
    return (typebuf);
}

/*
 * Return a string for the type.
 */
const char* p_section(int section, int opcode) {
    const struct res_sym* symbols;

    switch (opcode) {
        case ns_o_update:
            symbols = p_update_section_syms;
            break;
        default:
            symbols = p_default_section_syms;
            break;
    }
    return (sym_ntos(symbols, section, (int*) 0));
}

/*
 * Return a mnemonic for class.
 */
const char* p_class(int cl) {
    int success;
    const char* result;
    static char classbuf[20];

    result = sym_ntos(p_class_syms, cl, &success);
    if (success) return (result);
    if (cl < 0 || cl > 0xffff) return ("BADCLASS");
    snprintf(classbuf, sizeof(classbuf), "CLASS%d", cl);
    return (classbuf);
}

/*
 * Return a string for the rcode.
 */
const char* p_rcode(int rcode) {
    return (sym_ntos(p_rcode_syms, rcode, (int*) 0));
}
