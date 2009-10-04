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

#include <stddef.h>	/* size_t */

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

#define SPF_LIST_HEAD(name, type)					\
struct name {								\
	struct type *cqh_first;		/* first element */		\
	struct type *cqh_last;		/* last element */		\
}

#define SPF_LIST_HEAD_INITIALIZER(head)					\
	{ SPF_LIST_END(&head), SPF_LIST_END(&head) }

#define SPF_LIST_ENTRY(type)						\
struct {								\
	struct type *cqe_next;		/* next element */		\
	struct type *cqe_prev;		/* previous element */		\
}

#define	SPF_LIST_FIRST(head)		((head)->cqh_first)
#define	SPF_LIST_LAST(head)		((head)->cqh_last)
#define	SPF_LIST_END(head)		((void *)(head))
#define	SPF_LIST_NEXT(elm)		((elm)->cqe.cqe_next)
#define	SPF_LIST_PREV(elm)		((elm)->cqe.cqe_prev)
#define	SPF_LIST_EMPTY(head)						\
	(SPF_LIST_FIRST(head) == SPF_LIST_END(head))

#define SPF_LIST_FOREACH(var, head)					\
	for((var) = SPF_LIST_FIRST(head);				\
	    (var) != SPF_LIST_END(head);					\
	    (var) = SPF_LIST_NEXT(var))

#define SPF_LIST_FOREACH_REVERSE(var, head)				\
	for((var) = SPF_LIST_LAST(head);					\
	    (var) != SPF_LIST_END(head);					\
	    (var) = SPF_LIST_PREV(var))

#define	SPF_LIST_INIT(head) do {						\
	(head)->cqh_first = SPF_LIST_END(head);				\
	(head)->cqh_last = SPF_LIST_END(head);				\
} while (0)

#define SPF_LIST_INSERT_AFTER(head, listelm, elm) do {			\
	(elm)->cqe.cqe_next = (listelm)->cqe.cqe_next;			\
	(elm)->cqe.cqe_prev = (listelm);				\
	if ((listelm)->cqe.cqe_next == SPF_LIST_END(head))		\
		(head)->cqh_last = (elm);				\
	else								\
		(listelm)->cqe.cqe_next->cqe.cqe_prev = (elm);		\
	(listelm)->cqe.cqe_next = (elm);				\
} while (0)

#define SPF_LIST_INSERT_BEFORE(head, listelm, elm) do {			\
	(elm)->cqe.cqe_next = (listelm);				\
	(elm)->cqe.cqe_prev = (listelm)->cqe.cqe_prev;			\
	if ((listelm)->cqe.cqe_prev == SPF_LIST_END(head))		\
		(head)->cqh_first = (elm);				\
	else								\
		(listelm)->cqe.cqe_prev->cqe.cqe_next = (elm);		\
	(listelm)->cqe.cqe_prev = (elm);				\
} while (0)

#define SPF_LIST_INSERT_HEAD(head, elm) do {				\
	(elm)->cqe.cqe_next = (head)->cqh_first;			\
	(elm)->cqe.cqe_prev = SPF_LIST_END(head);			\
	if ((head)->cqh_last == SPF_LIST_END(head))			\
		(head)->cqh_last = (elm);				\
	else								\
		(head)->cqh_first->cqe.cqe_prev = (elm);		\
	(head)->cqh_first = (elm);					\
} while (0)

#define SPF_LIST_INSERT_TAIL(head, elm) do {				\
	(elm)->cqe.cqe_next = SPF_LIST_END(head);			\
	(elm)->cqe.cqe_prev = (head)->cqh_last;				\
	if ((head)->cqh_first == SPF_LIST_END(head))			\
		(head)->cqh_first = (elm);				\
	else								\
		(head)->cqh_last->cqe.cqe_next = (elm);			\
	(head)->cqh_last = (elm);					\
} while (0)

#define	SPF_LIST_REMOVE(head, elm) do {					\
	if ((elm)->cqe.cqe_next == SPF_LIST_END(head))			\
		(head)->cqh_last = (elm)->cqe.cqe_prev;			\
	else								\
		(elm)->cqe.cqe_next->cqe.cqe_prev =			\
		    (elm)->cqe.cqe_prev;				\
	if ((elm)->cqe.cqe_prev == SPF_LIST_END(head))			\
		(head)->cqh_first = (elm)->cqe.cqe_next;		\
	else								\
		(elm)->cqe.cqe_prev->cqe.cqe_next =			\
		    (elm)->cqe.cqe_next;				\
} while (0)

#define SPF_LIST_REPLACE(head, elm, elm2) do {				\
	if (((elm2)->cqe.cqe_next = (elm)->cqe.cqe_next) ==		\
	    SPF_LIST_END(head))						\
		(head).cqh_last = (elm2);				\
	else								\
		(elm2)->cqe.cqe_next->cqe.cqe_prev = (elm2);		\
	if (((elm2)->cqe.cqe_prev = (elm)->cqe.cqe_prev) ==		\
	    SPF_LIST_END(head))						\
		(head).cqh_first = (elm2);				\
	else								\
		(elm2)->cqe.cqe_prev->cqe.cqe_next = (elm2);		\
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
	SPF_NONE      = 0,
	SPF_TEMPERROR = 'e',
	SPF_PERMERROR = 'E',
	SPF_PASS      = '+',
	SPF_FAIL      = '-',
	SPF_SOFTFAIL  = '~',
	SPF_NEUTRAL   = '?',
}; /* enum spf_result */


#define SPF_ISMODIFIER(type) ((type) & 0x20)

enum spf_modifier {
	SPF_REDIRECT = 0x20,
	SPF_EXP,
	SPF_UNKNOWN,
}; /* enum spf_modifier */


/** forward definitions */
typedef unsigned spf_macros_t;


struct spf_all {
	enum spf_mechanism type;
	enum spf_result result;
	spf_macros_t macros;
}; /* struct spf_all */


struct spf_include {
	enum spf_mechanism type;
	enum spf_result result;
	spf_macros_t macros;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_include */


struct spf_a {
	enum spf_mechanism type;
	enum spf_result result;
	spf_macros_t macros;

	char domain[SPF_MAXDN + 1];

	unsigned prefix4, prefix6;
}; /* struct spf_a */


struct spf_mx {
	enum spf_mechanism type;
	enum spf_result result;
	spf_macros_t macros;

	char domain[SPF_MAXDN + 1];

	unsigned prefix4, prefix6;
}; /* struct spf_mx */


struct spf_ptr {
	enum spf_mechanism type;
	enum spf_result result;
	spf_macros_t macros;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_ptr */


struct spf_ip4 {
	enum spf_mechanism type;
	enum spf_result result;
	spf_macros_t macros;

	struct in_addr addr;
	unsigned prefix;
}; /* struct spf_ip4 */


struct spf_ip6 {
	enum spf_mechanism type;
	enum spf_result result;
	spf_macros_t macros;

	struct in6_addr addr;
	unsigned prefix;
}; /* struct spf_ip6 */


struct spf_exists {
	enum spf_mechanism type;
	enum spf_result result;
	spf_macros_t macros;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_exists */


struct spf_redirect {
	enum spf_modifier type;
	enum spf_result result;
	spf_macros_t macros;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_redirect */


struct spf_exp {
	enum spf_modifier type;
	enum spf_result result;
	spf_macros_t macros;

	char domain[SPF_MAXDN + 1];
}; /* struct spf_exp */


struct spf_unknown {
	enum spf_modifier type;
	enum spf_result result;
	spf_macros_t macros;

	char name[(SPF_MAXDN / 2) + 1];
	char value[(SPF_MAXDN / 2) + 1];
}; /* struct spf_unknown */


struct spf_term {
	union {
		struct {
			int type;		/* enum spf_mechanism | enum spf_modifier */
			enum spf_result result;	/* (mechanisms only) */
			spf_macros_t macros;
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

	SPF_LIST_ENTRY(spf_term) cqe;
}; /* struct spf_term */


struct spf_rr {
	SPF_LIST_HEAD(spf_terms, spf_term) terms;
	unsigned count;

	struct {
		int lc;
		char near[64];
	} error;
}; /* struct spf_rr */

void spf_rr_init(struct spf_rr *);

int spf_rr_parse(struct spf_rr *, const void *, size_t);

void spf_rr_reset(struct spf_rr *);


struct spf_env {
	char s[64 + 1 + SPF_MAXDN + 1];
	char l[64 + 1];
	char o[SPF_MAXDN + 1];
	char d[SPF_MAXDN + 1];
	char i[63 + 1]; /* IPv6 in long nybble format (32 nybbles + 31 "."s) */
	char p[SPF_MAXDN + 1];
	char v[SPF_MAX(sizeof "in-addr", sizeof "ip6")];
	char h[SPF_MAXDN + 1];

	char c[SPF_MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN) + 1];
	char r[SPF_MAXDN + 1];
	char t[32];
}; /* struct spf_env */

int spf_env_init(struct spf_env *, int, const void *, const char *, const char *);

size_t spf_env_set(struct spf_env *, int, const char *);

size_t spf_env_get(char *, size_t, int, const struct spf_env *);


_Bool spf_used(spf_macros_t, int);

size_t spf_expand(char *, size_t, spf_macros_t *, const char *, const struct spf_env *, int *);

/** return set of macros used in expansion */
spf_macros_t spf_macros(const char *, const struct spf_env *);


struct spf_resolver;

struct spf_limits {
	unsigned querymax; /* max # terms which require a query */
}; /* struct spf_limits */

extern const struct spf_limits spf_safelimits;

struct spf_resolver *spf_res_open(const struct spf_env *, const struct spf_limits *, int *);

void spf_res_close(struct spf_resolver *);

enum spf_result spf_res_check(struct spf_resolver *, int *);


#endif /* SPF_H */
