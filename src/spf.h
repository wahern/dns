/* ==========================================================================
 * spf.h - "spf.c", a Sender Policy Framework library.
 * --------------------------------------------------------------------------
 * Copyright (c) 2009  William Ahern
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */
#ifndef SPF_H
#define SPF_H


#include <netinet/in.h>	/* struct in_addr struct in6_addr */


#define SPF_MIN(a, b) (((a) < (b))? (a) : (b))
#define SPF_MAX(a, b) (((a) > (b))? (a) : (b))

#define SPF_MAXDN 255


/*
 * SPF queue macros from original BSD queue macros, OpenBSD 4.5 vintage.
 *
 * Copyright (c) 1991, 1993
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
#define SPF_HEAD(type) \
	struct { struct type *tqh_first; struct type **tqh_last; }

#define SPF_ENTRY(type) \
	struct { struct type *tqe_next; struct type **tqe_prev; }

#define	SPF_FIRST(head) ((head)->tqh_first)
#define	SPF_END(head) 0
#define	SPF_NEXT(elm) ((elm)->tqe.tqe_next)
#define	SPF_EMPTY(head) \
	(SPF_FIRST(head) == SPF_END(head))

#define SPF_FOREACH(var, head) \
	for((var) = SPF_FIRST(head); (var) != SPF_END(head); (var) = SPF_NEXT(var))

#define	SPF_INIT(head) \
	do { (head)->tqh_first = 0; (head)->tqh_last = &(head)->tqh_first; } while (0)

#define SPF_INSERT_HEAD(head, elm) do { \
	if (((elm)->tqe.tqe_next = (head)->tqh_first)) \
		(head)->tqh_first->tqe.tqe_prev = &(elm)->tqe.tqe_next; \
	else \
		(head)->tqh_last = &(elm)->tqe.tqe_next; \
	(head)->tqh_first = (elm); \
	(elm)->tqe.tqe_prev = &(head)->tqh_first; \
} while (0)

#define SPF_INSERT_TAIL(head, elm) do { \
	(elm)->tqe.tqe_next = 0; \
	(elm)->tqe.tqe_prev = (head)->tqh_last; \
	*(head)->tqh_last = (elm); \
	(head)->tqh_last = &(elm)->tqe.tqe_next; \
} while (0)

#define SPF_INSERT_AFTER(head, listelm, elm) do { \
	if (((elm)->tqe.tqe_next = (listelm)->tqe.tqe_next)) \
		(elm)->tqe.tqe_next->tqe.tqe_prev = &(elm)->tqe.tqe_next; \
	else \
		(head)->tqh_last = &(elm)->tqe.tqe_next; \
	(listelm)->tqe.tqe_next = (elm); \
	(elm)->tqe.tqe_prev = &(listelm)->tqe.tqe_next; \
} while (0)

#define	SPF_INSERT_BEFORE(listelm, elm) do { \
	(elm)->tqe.tqe_prev = (listelm)->tqe.tqe_prev; \
	(elm)->tqe.tqe_next = (listelm); \
	*(listelm)->tqe.tqe_prev = (elm); \
	(listelm)->tqe.tqe_prev = &(elm)->tqe.tqe_next; \
} while (0)

#define SPF_REMOVE(head, elm) do { \
	if (((elm)->tqe.tqe_next)) \
		(elm)->tqe.tqe_next->tqe.tqe_prev = (elm)->tqe.tqe_prev; \
	else \
		(head)->tqh_last = (elm)->tqe.tqe_prev; \
	*(elm)->tqe.tqe_prev = (elm)->tqe.tqe_next; \
} while (0)

#define SPF_REPLACE(head, elm, elm2) do { \
	if (((elm2)->tqe.tqe_next = (elm)->tqe.tqe_next)) \
		(elm2)->tqe.tqe_next->tqe.tqe_prev = &(elm2)->tqe.tqe_next; \
	else \
		(head)->tqh_last = &(elm2)->tqe.tqe_next; \
	(elm2)->tqe.tqe_prev = (elm)->tqe.tqe_prev; \
	*(elm2)->tqe.tqe_prev = (elm2); \
} while (0)

/** end BSD queue macros */


#define SPF_ISMECHANISM(type) ((type) & 0x10)

enum spf_mechanism {
	SPF_ALL = 0x10,
	SPF_INCLUDE,
	SPF_A,
	SPF_MX,
	SPF_PTR,
	SPF_IP4,
	SPF_IP6,
	SPF_EXISTS,
}; /* enum spf_mechanism */


enum spf_result {
	SPF_PASS     = '+',
	SPF_FAIL     = '-',
	SPF_SOFTFAIL = '~',
	SPF_NEUTRAL  = '?',
}; /* enum spf_result */


#define SPF_ISMODIFIER(type) ((type) & 0x20)

enum spf_modifier {
	SPF_REDIRECT = 0x20,
	SPF_EXP,
	SPF_UNKNOWN,
}; /* enum spf_modifier */


struct spf_all {
	enum spf_mechanism type;
	enum spf_result result;
}; /* struct spf_all */


struct spf_include {
	enum spf_mechanism type;
	enum spf_result result;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_include */


struct spf_a {
	enum spf_mechanism type;
	enum spf_result result;

	char domain[SPF_MAXDN + 1];

	unsigned prefix4, prefix6;
}; /* struct spf_a */


struct spf_mx {
	enum spf_mechanism type;
	enum spf_result result;

	char domain[SPF_MAXDN + 1];

	unsigned prefix4, prefix6;
}; /* struct spf_mx */


struct spf_ptr {
	enum spf_mechanism type;
	enum spf_result result;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_ptr */


struct spf_ip4 {
	enum spf_mechanism type;
	enum spf_result result;

	struct in_addr addr;
	unsigned prefix;
}; /* struct spf_ip4 */


struct spf_ip6 {
	enum spf_mechanism type;
	enum spf_result result;

	struct in6_addr addr;
	unsigned prefix;
}; /* struct spf_ip6 */


struct spf_exists {
	enum spf_mechanism type;
	enum spf_result result;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_exists */


struct spf_redirect {
	enum spf_modifier type;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_redirect */


struct spf_exp {
	enum spf_modifier type;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_exp */


struct spf_unknown {
	enum spf_modifier type;

	char name[(SPF_MAXDN / 2) + 1];
	char value[(SPF_MAXDN / 2) + 1];
}; /* struct spf_unknown */


struct spf_term {
	union {
		struct {
			int type;		/* enum spf_mechanism | enum spf_modifier */
			enum spf_result result;	/* (mechanisms only) */
		};

		struct spf_all all;
		struct spf_include include;
		struct spf_a a;
		struct spf_mx mx;
		struct spf_ptr ptr;
		struct spf_ip4 ip4;
		struct spf_ip6 ip6;
		struct spf_exists exists;

		struct spf_redirect redirect;
		struct spf_exp exp;
		struct spf_unknown unknown;
	};

	SPF_ENTRY(spf_term) tqe;
}; /* struct spf_term */


enum spf_rtype {
	SPF_T_TXT = 16,
	SPF_T_SPF = 99,
}; /* spf_rtype */

struct spf_rr {
	char qname[SPF_MAXDN + 1];
	int rtype;

	struct {
		int lc;
		char near[16];
	} error;

	SPF_HEAD(spf_rr) terms;

	SPF_ENTRY(spf_rr) tqe;
}; /* struct spf_rr */


struct spf_rr *spf_rr_open(const char *, enum spf_rtype, int *);

void spf_rr_close(struct spf_rr *);

int spf_rr_parse(struct spf_rr *, const void *, size_t);


struct spf_env {
	char s[64 + 1 + SPF_MAXDN + 1];
	char l[64 + 1];
	char o[SPF_MAXDN + 1];
	char d[SPF_MAXDN + 1];
	char i[SPF_MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN) + 1];
	char p[SPF_MAXDN + 1];
	char v[SPF_MAX(sizeof "in-addr", sizeof "ip6")];
	char h[SPF_MAXDN + 1];

	char c[SPF_MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN) + 1];
	char r[SPF_MAXDN + 1];
	char t[32];
}; /* struct spf_env */


struct spf_env *spf_env_init(struct spf_env *);



#endif /* SPF_H */
