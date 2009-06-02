/* ==========================================================================
 * spf.rl - "spf.c", a Sender Policy Framework library.
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
#include <stddef.h>	/* size_t */
#include <stdlib.h>	/* malloc(3) free(3) */

#include <ctype.h>	/* isgraph(3) isdigit(3) tolower(3) */

#include <string.h>	/* memcpy(3) strlen(3) strsep(3) strcmp(3) */

#include <errno.h>	/* EINVAL ENAMETOOLONG E2BIG errno */

#include <assert.h>	/* assert(3) */

#include <time.h>	/* time(3) */

#include <sys/socket.h>	/* AF_INET AF_INET6 */

#include <unistd.h>	/* gethostname(3) */

#include <netinet/in.h>	/* struct in_addr struct in6_addr */

#include "dns.h"
#include "spf.h"


#if SPF_DEBUG
#include <stdio.h> /* stderr fprintf(3) */

int spf_debug;

#undef SPF_DEBUG
#define SPF_DEBUG spf_debug
#define SPF_TRACE (spf_debug > 1)

#define SPF_SAY_(fmt, ...) fprintf(stderr, fmt "%.1s", __func__, __LINE__, __VA_ARGS__)
#define SPF_SAY(...) SPF_SAY_(">>>> (%s:%d) " __VA_ARGS__, "\n")
#define SPF_HAI SPF_SAY("HAI")
#else
#define SPF_DEBUG 0
#define SPF_TRACE 0

#define SPF_SAY(...)
#define SPF_HAI
#endif /* SPF_DEBUG */


#define spf_lengthof(a) (sizeof (a) / sizeof (a)[0])
#define spf_endof(a) (&(a)[spf_lengthof((a))])


static size_t spf_itoa(char *dst, size_t lim, unsigned i) {
	unsigned r, d = 1000000000, p = 0;
	size_t dp = 0;

	if (i) {
		do {
			if ((r = i / d) || p) {
				i -= r * d;

				p++;

				if (dp < lim)
					dst[dp] = '0' + r;
				dp++;
			}
		} while (d /= 10);
	} else {
		if (dp < lim)
			dst[dp] = '0';
		dp++;
	}

	if (lim)
		dst[SPF_MIN(dp, lim - 1)] = '\0';

	return dp;
} /* spf_itoa() */


unsigned spf_atoi(const char *src) {
	unsigned i = 0;

	while (isdigit((unsigned char)*src)) {
		i *= 10;
		i += *src++ - '0';
	}

	return i;
} /* spf_atoi() */


unsigned spf_xtoi(const char *src) {
	static const unsigned char tobase[] =
		{ [0 ... 255] = 0xf0,
		  ['0'] = 0x0, ['1'] = 0x1, ['2'] = 0x2, ['3'] = 0x3, ['4'] = 0x4,
		  ['5'] = 0x5, ['6'] = 0x6, ['7'] = 0x7, ['8'] = 0x8, ['9'] = 0x9,
		  ['a'] = 0xa, ['b'] = 0xb, ['c'] = 0xc, ['d'] = 0xd, ['e'] = 0xe, ['f'] = 0xf,
		  ['A'] = 0xA, ['B'] = 0xB, ['C'] = 0xC, ['D'] = 0xD, ['E'] = 0xE, ['F'] = 0xF };
	unsigned n, i = 0;

	while (!(0xf0 & (n = tobase[0xff & (unsigned char)*src++]))) {
		i <<= 4;
		i |= n;
	}

	return i;
} /* spf_xtoi() */


size_t spf_itox(char *dst, size_t lim, unsigned i) {
	static const char tohex[] = "0123456789abcdef";
	unsigned r, d = 0x10000000, p = 0;
	size_t dp = 0;

	if (i) {
		do {
			if ((r = i / d) || p) {
				i -= r * d;

				p++;

				if (dp < lim)
					dst[dp] = tohex[r];
				dp++;
			}
		} while (d /= 16);
	} else {
		if (dp < lim)
			dst[dp] = '0';

		dp++;
	}

	if (lim)
		dst[SPF_MIN(dp, lim - 1)] = '\0';

	return dp;
} /* spf_itox() */


static size_t spf_strlcpy(char *dst, const char *src, size_t lim) {
	char *dp = dst; char *de = &dst[lim]; const char *sp = src;

	if (dp < de) {
		do {
			if ('\0' == (*dp++ = *sp++))
				return sp - src - 1;
		} while (dp < de);

		dp[-1]	= '\0';
	}

	while (*sp++ != '\0')
		;;

	return sp - src - 1;
} /* spf_strlcpy() */


static unsigned spf_split(unsigned max, char **argv, char *src, const char *delim, _Bool empty) {
	unsigned argc = 0;
	char *arg;

	do {
		if ((arg = strsep(&src, delim)) && (*arg || empty)) {
			if (argc < max)
				argv[argc] = arg;

			argc++;
		}
	} while (arg);

	if (max)
		argv[SPF_MIN(argc, max - 1)] = 0;

	return argc;
} /* spf_split() */


/*
 * Normalize domains:
 *
 *   (1) remove leading dots
 *   (2) remove extra dots
 *   (3) add/remove/leave anchor
 */
size_t spf_trim(char *dst, const char *src, size_t lim, int anchor) {
	size_t dp = 0, sp = 0;
	int lc = 0;

	/* trim any leading dot(s) */
	while (src[sp] == '.')
		sp++;

	while (src[sp]) {
		lc = src[sp];

		if (dp < lim)
			dst[dp] = src[sp];

		sp++; dp++;

		/* trim extra dot(s) */
		while (lc == '.' && src[sp] == '.')
			sp++;
	}

	if (anchor < 0) {
		if (lc == '.')
			dp--;
	} else if (anchor > 0) {
		if (lc != '.') {
			if (dp < lim)
				dst[dp] = '.';

			dp++;
		}
	}

	if (lim > 0)
		dst[SPF_MIN(dp, lim - 1)] = '\0';

	return dp;
} /* spf_trim() */


char *spf_tolower(char *src) {
	unsigned char *p = (unsigned char *)src;

	while (*p) {
		*p = tolower(*p);
		++p;
	}

	return src;
} /* spf_tolower() */


size_t spf_4top(char *dst, size_t lim, const struct in_addr *ip) {
	char tmp[16];
	size_t len;
	unsigned i;

	len = spf_itoa(tmp, sizeof tmp, 0xff & (ntohl(ip->s_addr) >> 24));

	for (i = 1; i < 4; i++) {
		tmp[len++] = '.';
		len += spf_itoa(&tmp[len], sizeof tmp - len, 0xff & (ntohl(ip->s_addr) >> (8 * (3 - i))));
	}

	return spf_strlcpy(dst, tmp, lim);
} /* spf_4top() */


/** a simple, optimistic IPv4 address string parser */
struct in_addr *spf_pto4(struct in_addr *ip, const char *src) {
	char *byte[4 + 1];
	char tmp[16];
	unsigned bytes, i, iaddr;

	spf_strlcpy(tmp, src, sizeof tmp);

	bytes = spf_split(spf_lengthof(byte), byte, tmp, ".", 1);
	iaddr = 0;

	for (i = 0; i < SPF_MIN(bytes, 4); i++) {
		iaddr <<= 8;
		iaddr |= 0xff & spf_atoi(byte[i]);
	}

	iaddr <<= 8 * (4 - i);

	ip->s_addr = htonl(iaddr);

	return ip;
} /* spf_pto4() */


#define SPF_6TOP_NYBBLE 1
#define SPF_6TOP_COMPAT 2
#define SPF_6TOP_MAPPED 4
#define SPF_6TOP_MIXED  (SPF_6TOP_COMPAT|SPF_6TOP_MAPPED)

size_t spf_6top(char *dst, size_t lim, const struct in6_addr *ip, int flags) {
	static const char tohex[] = "0123456789abcdef";
	unsigned short group[8];
	char tmp[SPF_MAX(40, 64)]; /* 40 for canon, 64 for nybbles (includes '\0') */
	size_t len;
	unsigned i;
	_Bool run, ran;

	len = 0;

	if (flags & SPF_6TOP_NYBBLE) {
		tmp[len++] = tohex[0x0f & (ip->s6_addr[0] >> 4)];
		tmp[len++] = '.';
		tmp[len++] = tohex[0x0f & (ip->s6_addr[0] >> 0)];

		for (i = 1; i < 16; i++) {
			tmp[len++] = '.';
			tmp[len++] = tohex[0x0f & (ip->s6_addr[i] >> 4)];
			tmp[len++] = '.';
			tmp[len++] = tohex[0x0f & (ip->s6_addr[i] >> 0)];
		}
	} else if (IN6_IS_ADDR_V4COMPAT(ip) && (flags & SPF_6TOP_COMPAT)) {
		tmp[len++] = ':';
		tmp[len++] = ':';

		len += spf_itoa(&tmp[len], sizeof tmp - len, ip->s6_addr[12]);

		for (i = 13; i < 16; i++) {
			tmp[len++] = '.';
			len += spf_itoa(&tmp[len], sizeof tmp - len, ip->s6_addr[i]);
		}
	} else if (IN6_IS_ADDR_V4MAPPED(ip) && (flags & SPF_6TOP_MAPPED)) {
		tmp[len++] = ':';
		tmp[len++] = ':';
		tmp[len++] = 'f';
		tmp[len++] = 'f';
		tmp[len++] = 'f';
		tmp[len++] = 'f';
		tmp[len++] = ':';

		len += spf_itoa(&tmp[len], sizeof tmp - len, ip->s6_addr[12]);

		for (i = 13; i < 16; i++) {
			tmp[len++] = '.';
			len += spf_itoa(&tmp[len], sizeof tmp - len, ip->s6_addr[i]);
		}
	} else {
		for (i = 0; i < 8; i++) {
			group[i] = (0xff00 & (ip->s6_addr[i * 2] << 8))
			         | (0x00ff & (ip->s6_addr[i * 2 + 1] << 0));
		}

		run = 0; ran = 0;

		if (group[0]) {
			len = spf_itox(tmp, sizeof tmp, group[0]);
		} else
			run++;

		for (i = 1; i < 8; i++) {
			if (group[i] || ran) {
				if (run) {
					tmp[len++] = ':';
					ran = 1; run = 0;
				}

				tmp[len++] = ':';
				len += spf_itox(&tmp[len], sizeof tmp - len, group[i]);
			} else
				run++;
		}

		if (run) {
			tmp[len++] = ':';
			tmp[len++] = ':';
		}
	}

	tmp[len] = '\0';

	return spf_strlcpy(dst, tmp, lim);
} /* spf_6top() */


/** a simple, optimistic IPv6 address string parser */
struct in6_addr *spf_pto6(struct in6_addr *ip, const char *src) {
	char *part[32 + 1]; /* 8 words or 32 nybbles */
	char tmp[64];
	unsigned short group[8] = { 0 };
	unsigned count, i, j, k;
	struct in_addr ip4;

	spf_strlcpy(tmp, src, sizeof tmp);

	count = spf_split(spf_lengthof(part), part, tmp, ":", 1);

	if (count > 1) {
		for (i = 0; i < SPF_MIN(count, 8); i++) {
			if (*part[i]) {
				if (strchr(part[i], '.')) {
					spf_pto4(&ip4, part[i]);

					group[i] = 0xffff & (ntohl(ip4.s_addr) >> 16);

					if (++i < 8)
						group[i] = 0xffff & ntohl(ip4.s_addr);
				} else {
					group[i] = spf_xtoi(part[i]);
				}
			} else {
				for (j = 7, k = count - 1; j > i && k > 0; j--, k--) {
					if (strchr(part[k], '.')) {
						spf_pto4(&ip4, part[k]);

						group[j] = 0xffff & ntohl(ip4.s_addr);

						if (--j >= 0)
							group[j] = 0xffff & (ntohl(ip4.s_addr) >> 16);
					} else {
						group[j] = spf_xtoi(part[k]);
					}
				}

				break;
			}
		}
	} else {
		spf_strlcpy(tmp, src, sizeof tmp);

		count = spf_split(spf_lengthof(part), part, tmp, ".", 1);
		count = SPF_MIN(count, 32);

		for (i = 0, j = 0; i < count; j++) {
			for (k = 0; k < 4 && i < count; k++, i++) {
				group[j] <<= 4;
				group[j] |= 0xf & spf_xtoi(part[i]);
			}

			group[j] <<= 4 * (4 - k);
		}
	}

	for (i = 0, j = 0; i < 8; i++) {
		ip->s6_addr[j++] = 0xff & (group[i] >> 8);
		ip->s6_addr[j++] = 0xff & (group[i] >> 0);
	}

	while (j < 16)
		ip->s6_addr[j++] = 0;

	return ip;
} /* spf_pto6() */


size_t spf_ntop(char *dst, size_t lim, int af, const void *ip, int flags) {
	if (af == AF_INET6)
		return spf_6top(dst, lim, ip, flags);
	else
		return spf_4top(dst, lim, ip);
} /* spf_ntop() */


struct spf_sbuf {
	unsigned end;

	_Bool overflow;

	char str[512];
}; /* struct spf_sbuf */

static void sbuf_init(struct spf_sbuf *sbuf) {
	memset(sbuf, 0, sizeof *sbuf);
} /* sbuf_init() */

static _Bool sbuf_putc(struct spf_sbuf *sbuf, int ch) {
	if (sbuf->end < sizeof sbuf->str - 1)
		sbuf->str[sbuf->end++] = ch;
	else
		sbuf->overflow = 1;

	return !sbuf->overflow;
} /* sbuf_putc() */

static _Bool sbuf_puts(struct spf_sbuf *sbuf, const char *src) {
	while (*src && sbuf_putc(sbuf, *src))
		src++;

	return !sbuf->overflow;
} /* sbuf_puts() */

static _Bool sbuf_putv(struct spf_sbuf *sbuf, const void *src, size_t len) {
	size_t lim = SPF_MIN(len, (sizeof sbuf->str - 1) - sbuf->end);

	memcpy(&sbuf->str[sbuf->end], src, lim);
	sbuf->end += lim;

	sbuf->overflow = (lim != len);

	return !sbuf->overflow;
} /* sbuf_putv() */

static _Bool sbuf_puti(struct spf_sbuf *sbuf, unsigned long i) {
	char tmp[32];

	spf_itoa(tmp, sizeof tmp, i);

	return sbuf_puts(sbuf, tmp);
} /* sbuf_puti() */

static _Bool sbuf_put4(struct spf_sbuf *sbuf, const struct in_addr *ip) {
	char tmp[16];

	spf_4top(tmp, sizeof tmp, ip);

	return sbuf_puts(sbuf, tmp);
} /* sbuf_put4() */

static _Bool sbuf_put6(struct spf_sbuf *sbuf, const struct in6_addr *ip) {
	char tmp[40];

	spf_6top(tmp, sizeof tmp, ip, SPF_6TOP_MIXED);

	return sbuf_puts(sbuf, tmp);
} /* sbuf_put6() */


const char *spf_strtype(int type) {
	switch (type) {
	case SPF_ALL:
		return "all";
	case SPF_INCLUDE:
		return "include";
	case SPF_A:
		return "a";
	case SPF_MX:
		return "mx";
	case SPF_PTR:
		return "ptr";
	case SPF_IP4:
		return "ip4";
	case SPF_IP6:
		return "ip6";
	case SPF_EXISTS:
		return "exists";
	case SPF_REDIRECT:
		return "redirect";
	case SPF_EXP:
		return "exp";
	default:
		return "[[[error]]]";
	}
} /* spf_strtype() */




static const struct spf_all all_initializer =
	{ .type = SPF_ALL, .result = SPF_PASS };

static void all_comp(struct spf_sbuf *sbuf, struct spf_all *all) {
	sbuf_putc(sbuf, all->result);
	sbuf_puts(sbuf, "all");
} /* all_comp() */

static _Bool all_match(struct spf_all *all, struct spf_env *env) {
	return 1;
} /* all_match() */


static const struct spf_include include_initializer =
	{ .type = SPF_INCLUDE, .result = SPF_PASS, .domain = "%{d}" };

static void include_comp(struct spf_sbuf *sbuf, struct spf_include *include) {
	sbuf_putc(sbuf, include->result);
	sbuf_puts(sbuf, "include");
	sbuf_putc(sbuf, ':');
	sbuf_puts(sbuf, include->domain);
} /* include_comp() */

static _Bool include_match(struct spf_include *include, struct spf_env *env) {
	return 0; /* should be treated specially */
} /* include_match() */


static const struct spf_a a_initializer =
	{ .type = SPF_A, .result = SPF_PASS, .domain = "%{d}", .prefix4 = 32, .prefix6 = 128 };

static void a_comp(struct spf_sbuf *sbuf, struct spf_a *a) {
	sbuf_putc(sbuf, a->result);
	sbuf_puts(sbuf, "a");
	sbuf_putc(sbuf, ':');
	sbuf_puts(sbuf, a->domain);
	sbuf_putc(sbuf, '/');
	sbuf_puti(sbuf, a->prefix4);
	sbuf_puts(sbuf, "//");
	sbuf_puti(sbuf, a->prefix6);
} /* a_comp() */

static _Bool a_match(struct spf_a *a, struct spf_env *env) {
	
} /* a_match() */


static const struct spf_mx mx_initializer =
	{ .type = SPF_MX, .result = SPF_PASS, .domain = "%{d}", .prefix4 = 32, .prefix6 = 128 };

static void mx_comp(struct spf_sbuf *sbuf, struct spf_mx *mx) {
	sbuf_putc(sbuf, mx->result);
	sbuf_puts(sbuf, "mx");
	sbuf_putc(sbuf, ':');
	sbuf_puts(sbuf, mx->domain);
	sbuf_putc(sbuf, '/');
	sbuf_puti(sbuf, mx->prefix4);
	sbuf_puts(sbuf, "//");
	sbuf_puti(sbuf, mx->prefix6);
} /* mx_comp() */


static const struct spf_ptr ptr_initializer =
	{ .type = SPF_PTR, .result = SPF_PASS, .domain = "%{d}" };

static void ptr_comp(struct spf_sbuf *sbuf, struct spf_ptr *ptr) {
	sbuf_putc(sbuf, ptr->result);
	sbuf_puts(sbuf, "ptr");
	sbuf_putc(sbuf, ':');
	sbuf_puts(sbuf, ptr->domain);
} /* ptr_comp() */


static const struct spf_ip4 ip4_initializer =
	{ .type = SPF_IP4, .result = SPF_PASS, .prefix = 32 };

static void ip4_comp(struct spf_sbuf *sbuf, struct spf_ip4 *ip4) {
	sbuf_putc(sbuf, ip4->result);
	sbuf_puts(sbuf, "ip4");
	sbuf_putc(sbuf, ':');
	sbuf_put4(sbuf, &ip4->addr);
	sbuf_putc(sbuf, '/');
	sbuf_puti(sbuf, ip4->prefix);
} /* ip4_comp() */


static const struct spf_ip6 ip6_initializer =
	{ .type = SPF_IP6, .result = SPF_PASS, .prefix = 128 };

static void ip6_comp(struct spf_sbuf *sbuf, struct spf_ip6 *ip6) {
	sbuf_putc(sbuf, ip6->result);
	sbuf_puts(sbuf, "ip6");
	sbuf_putc(sbuf, ':');
	sbuf_put6(sbuf, &ip6->addr);
	sbuf_putc(sbuf, '/');
	sbuf_puti(sbuf, ip6->prefix);
} /* ip6_comp() */


static const struct spf_exists exists_initializer =
	{ .type = SPF_EXISTS, .result = SPF_PASS, .domain = "%{d}" };

static void exists_comp(struct spf_sbuf *sbuf, struct spf_exists *exists) {
	sbuf_putc(sbuf, exists->result);
	sbuf_puts(sbuf, "exists");
	sbuf_putc(sbuf, ':');
	sbuf_puts(sbuf, exists->domain);
} /* exists_comp() */


static const struct spf_redirect redirect_initializer =
	{ .type = SPF_REDIRECT };

static void redirect_comp(struct spf_sbuf *sbuf, struct spf_redirect *redirect) {
	sbuf_puts(sbuf, "redirect");
	sbuf_putc(sbuf, '=');
	sbuf_puts(sbuf, redirect->domain);
} /* redirect_comp() */


static const struct spf_exp exp_initializer =
	{ .type = SPF_EXP };

static void exp_comp(struct spf_sbuf *sbuf, struct spf_exp *exp) {
	sbuf_puts(sbuf, "exp");
	sbuf_putc(sbuf, '=');
	sbuf_puts(sbuf, exp->domain);
} /* exp_comp() */


static const struct spf_unknown unknown_initializer =
	{ .type = SPF_UNKNOWN };

static void unknown_comp(struct spf_sbuf *sbuf, struct spf_unknown *unknown) {
	sbuf_puts(sbuf, unknown->name);
	sbuf_putc(sbuf, '=');
	sbuf_puts(sbuf, unknown->value);
} /* unknown_comp() */


static const struct {
	const void *initializer;
	size_t size;
	void (*comp)();
	_Bool (*match)();
} spf_term[] = {
	[SPF_ALL]     = { &all_initializer, sizeof all_initializer, &all_comp },
	[SPF_INCLUDE] = { &include_initializer, sizeof include_initializer, &include_comp },
	[SPF_A]       = { &a_initializer, sizeof a_initializer, &a_comp },
	[SPF_MX]      = { &mx_initializer, sizeof mx_initializer, &mx_comp },
	[SPF_PTR]     = { &ptr_initializer, sizeof ptr_initializer, &ptr_comp },
	[SPF_IP4]     = { &ip4_initializer, sizeof ip4_initializer, &ip4_comp },
	[SPF_IP6]     = { &ip6_initializer, sizeof ip6_initializer, &ip6_comp },
	[SPF_EXISTS]  = { &exists_initializer, sizeof exists_initializer, &exists_comp },

	[SPF_REDIRECT] = { &redirect_initializer, sizeof redirect_initializer, &redirect_comp },
	[SPF_EXP]      = { &exp_initializer, sizeof exp_initializer, &exp_comp },
	[SPF_UNKNOWN]  = { &unknown_initializer, sizeof unknown_initializer, &unknown_comp },
}; /* spf_term[] */

static char *term_comp(struct spf_sbuf *sbuf, void *term) {
	spf_term[((struct spf_term *)term)->type].comp(sbuf, term);

	return sbuf->str;
} /* term_comp() */


%%{
	machine spf_grammar;
	alphtype unsigned char;

	action oops {
		const unsigned char *part;

		rr->spf.error.lc = fc;

		if (p - (unsigned char *)rdata >= (sizeof rr->spf.error.near / 2))
			part = p - (sizeof rr->spf.error.near / 2);
		else
			part = rdata;

		memset(rr->spf.error.near, 0, sizeof rr->spf.error.near);
		memcpy(rr->spf.error.near, part, SPF_MIN(sizeof rr->spf.error.near - 1, pe - part));

		if (SPF_DEBUG) {
			if (isgraph(rr->spf.error.lc))
				SPF_SAY("`%c' invalid near `%s'", rr->spf.error.lc, rr->spf.error.near);
			else
				SPF_SAY("error near `%s'", rr->spf.error.near);
		}

		error = EINVAL;

		goto error;
	}

	action term_begin {
		result = SPF_PASS;
		memset(&term, 0, sizeof term);
		sbuf_init(&domain);
		prefix4 = 32; prefix6 = 128;
	}

	action term_end {
		if (term.type) {
			struct spf_term *term_;

			if (SPF_TRACE)
				SPF_SAY("term -> %s", term_comp(&(struct spf_sbuf){ 0 }, &term));

			if (!(term_ = malloc(sizeof *term_)))
				{ error = errno; goto error; }

			*term_ = term;

			SPF_INSERT_TAIL(&rr->spf.terms, term_);
		}
	}

	action all_begin {
		term.all    = all_initializer;
		term.result = result;
	}

	action all_end {
	}

	action include_begin {
		term.include = include_initializer;
		term.result  = result;
	}

	action include_end {
		if (*domain.str)
			spf_trim(term.include.domain, domain.str, sizeof term.include.domain, 0);
	}

	action a_begin {
		term.a      = a_initializer;
		term.result = result;
	}

	action a_end {
		if (*domain.str)
			spf_trim(term.a.domain, domain.str, sizeof term.a.domain, 0);

		term.a.prefix4 = prefix4;
		term.a.prefix6 = prefix6;
	}

	action mx_begin {
		term.mx    = mx_initializer;
		term.result = result;
	}

	action mx_end {
		if (*domain.str)
			spf_trim(term.mx.domain, domain.str, sizeof term.mx.domain, 0);

		term.mx.prefix4 = prefix4;
		term.mx.prefix6 = prefix6;
	}

	action ptr_begin {
		term.ptr    = ptr_initializer;
		term.result = result;
	}

	action ptr_end {
		if (*domain.str)
			spf_trim(term.ptr.domain, domain.str, sizeof term.ptr.domain, 0);
	}

	action ip4_begin {
		term.ip4    = ip4_initializer;
		term.result = result;
	}

	action ip4_end {
		spf_pto4(&term.ip4.addr, domain.str);
		term.ip4.prefix = prefix4;
	}

	action ip6_begin {
		term.ip6    = ip6_initializer;
		term.result = result;
	}

	action ip6_end {
		spf_pto6(&term.ip6.addr, domain.str);
		term.ip6.prefix = prefix6;
	}

	action exists_begin {
		term.exists = exists_initializer;
		term.result = result;
	}

	action exists_end {
		if (*domain.str)
			spf_trim(term.exists.domain, domain.str, sizeof term.exists.domain, 0);
	}

	action redirect_begin {
		term.redirect = redirect_initializer;
	}

	action redirect_end {
		if (*domain.str)
			spf_trim(term.redirect.domain, domain.str, sizeof term.redirect.domain, 0);
	}

	action exp_begin {
		term.exp = exp_initializer;
	}

	action exp_end {
		if (*domain.str)
			spf_trim(term.exp.domain, domain.str, sizeof term.exp.domain, 0);
	}

	action unknown_begin {
		sbuf_init(&name);
		sbuf_init(&value);
	}

	action unknown_end {
		term.unknown = unknown_initializer;

		spf_strlcpy(term.unknown.name, name.str, sizeof term.unknown.name);
		spf_strlcpy(term.unknown.value, value.str, sizeof term.unknown.value);
	}

	#
	# SPF RR grammar per RFC 4408 Sec. 15 App. A.
	#
	blank = [ \t];
	name  = alpha (alnum | "-" | "_" | ".")*;

	delimiter     = "." | "-" | "+" | "," | "/" | "_" | "=";
	transformers  = digit* "r"i?;

	macro_letter  = "s"i | "l"i | "o"i | "d"i | "i"i | "p"i | "v"i | "h"i | "c"i | "r"i | "t"i;
	macro_literal = (0x21 .. 0x24) | (0x26 .. 0x7e);
	macro_expand  = ("%{" macro_letter transformers delimiter* "}") | "%%" | "%_" | "%-";
	macro_string  = (macro_expand | macro_literal)*;

	toplabel       = (digit* alpha alnum*) | (alnum+ "-" (alnum | "-")* alnum);
	domain_end     = ("." toplabel "."?) | macro_expand;
	domain_literal = (0x21 .. 0x24) | (0x26 .. 0x2e) | (0x30 .. 0x7e);
	domain_macro   = (macro_expand | domain_literal)*;
	domain_spec    = (domain_macro domain_end) ${ sbuf_putc(&domain, fc); };

	qnum        = ("0" | ("3" .. "9"))
	            | ("1" digit{0,2})
	            | ("2" ( ("0" .. "4" digit?)?
	                   | ("5" ("0" .. "4")?)?
	                   | ("6" .. "9")?
	                   )
	              );
	ip4_network = (qnum "." qnum "." qnum "." qnum) ${ sbuf_putc(&domain, fc); };
	ip6_network = (xdigit | ":" | ".")+ ${ sbuf_putc(&domain, fc); };

	ip4_cidr_length  = "/" digit+ >{ prefix4 = 0; } ${ prefix4 *= 10; prefix4 += fc - '0'; };
	ip6_cidr_length  = "/" digit+ >{ prefix6 = 0; } ${ prefix6 *= 10; prefix6 += fc - '0'; };
	dual_cidr_length = ip4_cidr_length? ("/" ip6_cidr_length)?;

	unknown  = name >unknown_begin ${ sbuf_putc(&name, fc); }
	           "=" macro_string ${ sbuf_putc(&value, fc); }
	           %unknown_end;
	exp      = "exp"i %exp_begin "=" domain_spec %exp_end;
	redirect = "redirect"i %redirect_begin "=" domain_spec %redirect_end;
	modifier = redirect | exp | unknown;

	exists  = "exists"i %exists_begin ":" domain_spec %exists_end;
	IP6     = "ip6"i %ip6_begin ":" ip6_network ip6_cidr_length? %ip6_end;
	IP4     = "ip4"i %ip4_begin ":" ip4_network ip4_cidr_length? %ip4_end;
	PTR     = "ptr"i %ptr_begin (":" domain_spec)? %ptr_end;
	MX      = "mx"i %mx_begin (":" domain_spec)? dual_cidr_length? %mx_end;
	A       = "a"i %a_begin (":" domain_spec)? dual_cidr_length? %a_end;
	inklude = "include"i %include_begin ":" domain_spec %include_end;
	all     = "all"i %all_begin %all_end;

	mechanism = all | inklude | A | MX | PTR | IP4 | IP6 | exists;
	qualifier = ("+" | "-" | "?" | "~") @{ result = fc; };
	directive = qualifier? mechanism;

	term      = blank+ (directive | modifier) >term_begin %term_end;
	version   = "v=spf1"i;
	record    = version term* blank*;

	main      := record $!oops;
}%%


static int spf_rr_parse_(struct spf_rr *rr, const void *rdata, size_t rdlen) {
	enum spf_result result = 0;
	struct spf_term term;
	struct spf_sbuf domain, name, value;
	unsigned prefix4 = 0, prefix6 = 0;
	const unsigned char *p, *pe, *eof;
	int cs, error;

	%% write data;

	p   = rdata;
	pe  = p + rdlen;
	eof = pe;

	%% write init;
	%% write exec;

	return 0;
error:
	return error;
} /* spf_rr_parse_() */


struct spf_rr *spf_rr_open(const char *qname, enum spf_rr_type qtype, int *error) {
	struct spf_rr *rr;

	if (!(rr = malloc(sizeof *rr)))
		goto syerr;

	memset(rr, 0, sizeof *rr);

	if (sizeof rr->qname <= spf_trim(rr->qname, qname, sizeof rr->qname, 0))
		{ *error = ENAMETOOLONG; goto error; }

	rr->qtype = qtype;

	switch (rr->qtype) {
	case SPF_RR_TXT:
		/* FALL THROUGH */
	case SPF_RR_SPF:
		SPF_INIT(&rr->spf.terms);

		break;
	case SPF_RR_PTR:
		/* FALL THROUGH */
	case SPF_RR_MX:
		/* FALL THROUGH */
	case SPF_RR_A:
		SPF_INIT(&rr->a.ips);

		break;
	} /* switch() */

	rr->nrefs++;

	return rr;
syerr:
	*error = errno;
error:
	free(rr);

	return 0;
} /* spf_rr_open() */


void spf_rr_close(struct spf_rr *rr) {
	struct spf_term *term;
	struct spf_ip *ip;

	if (!rr || --rr->nrefs > 0)
		return;

	assert(rr->nrefs == 0);

	switch (rr->qtype) {
	case SPF_RR_TXT:
		/* FALL THROUGH */
	case SPF_RR_SPF:
		while ((term = SPF_FIRST(&rr->spf.terms))) {
			SPF_REMOVE(&rr->spf.terms, term);
			free(term);
		}

		break;
	case SPF_RR_PTR:
		/* FALL THROUGH */
	case SPF_RR_MX:
		/* FALL THROUGH */
	case SPF_RR_A:
		while ((ip = SPF_FIRST(&rr->a.ips))) {
			SPF_REMOVE(&rr->a.ips, ip);
			free(ip);
		}

		break;
	} /* switch() */

	free(rr);
} /* spf_rr_close() */


int spf_rr_parse(struct spf_rr *rr, const void *str, size_t len) {
	struct spf_sbuf sbuf = { 0 };
	struct spf_ip *ip;
	int error = 0;

	switch (rr->qtype) {
	case SPF_RR_TXT:
		/* FALL THROUGH */
	case SPF_RR_SPF:
		return spf_rr_parse_(rr, str, len);
	case SPF_RR_A:
		/* FALL THROUGH */
	case SPF_RR_PTR:
		/* FALL THROUGH */
	case SPF_RR_MX:
		if (!sbuf_putv(&sbuf, str, len))
			return EINVAL;

		return 0;
	default:
		assert(!"invalid SPF record data type");
	} /* switch() */
} /* spf_rr_parse() */


int spf_init(struct spf_env *env, int af, const void *ip, const char *domain, const char *sender) {
	memset(env->r, 0, sizeof env->r);

	if (af == AF_INET6) {
		spf_6top(env->i, sizeof env->i, ip, SPF_6TOP_NYBBLE);
		spf_6top(env->c, sizeof env->c, ip, SPF_6TOP_MIXED);

		spf_strlcpy(env->v, "ip6", sizeof env->v);
	} else {
		spf_4top(env->i, sizeof env->i, ip);
		spf_4top(env->c, sizeof env->c, ip);

		spf_strlcpy(env->v, "in-addr", sizeof env->v);
	}

	spf_strlcpy(env->p, "unknown", sizeof env->p);
	spf_strlcpy(env->r, "unknown", sizeof env->r);

	spf_itoa(env->t, sizeof env->t, (unsigned long)time(0));

	return 0;
} /* spf_init() */


static size_t spf_get_(char **field, int which, struct spf_env *env) {
	switch (tolower((unsigned char)which)) {
	case 's':
		*field = env->s;
		return sizeof env->s;
	case 'l':
		*field = env->l;
		return sizeof env->l;
	case 'o':
		*field = env->o;
		return sizeof env->o;
	case 'd':
		*field = env->d;
		return sizeof env->d;
	case 'i':
		*field = env->i;
		return sizeof env->i;
	case 'p':
		*field = env->p;
		return sizeof env->p;
	case 'v':
		*field = env->v;
		return sizeof env->v;
	case 'h':
		*field = env->h;
		return sizeof env->h;
	case 'c':
		*field = env->c;
		return sizeof env->c;
	case 'r':
		*field = env->r;
		return sizeof env->r;
	case 't':
		*field = env->t;
		return sizeof env->t;
	default:
		*field = 0;
		return 0;
	}
} /* spf_get_() */


size_t spf_get(char *dst, size_t lim, int which, const struct spf_env *env) {
	char *src;

	if (!spf_get_(&src, which, (struct spf_env *)env))
		return 0;

	return spf_strlcpy(dst, src, lim);
} /* spf_get() */


size_t spf_set(struct spf_env *env, int which, const char *src) {
	size_t lim, len;
	char *dst;

	if (!(lim = spf_get_(&dst, which, (struct spf_env *)env)))
		return strlen(src);

	len = spf_strlcpy(dst, src, lim);

	return SPF_MIN(lim - 1, len);
} /* spf_set() */


static size_t spf_expand_(char *dst, size_t lim, const char *src, const struct spf_env *env, int *error) {
	char field[512], *part[128], *tmp;
	const char *delim = ".";
	size_t len, dp = 0, sp = 0;
	int macro = 0;
	unsigned keep = 0;
	unsigned i, j, count;
	_Bool tr = 0, rev = 0;

	if (!(macro = *src))
		return 0;

	while (isdigit((unsigned char)src[++sp])) {
		keep *= 10;
		keep += src[sp] - '0';
		tr   = 1;
	}

	if (src[sp] == 'r')
		{ tr = 1; rev = 1; ++sp; }

	if (src[sp]) {
		delim = &src[sp];
		tr = 1;
	}

	if (!(len = spf_get(field, sizeof field, macro, env)))
		return 0;
	else if (len >= sizeof field)
		goto toolong;

	if (!tr)
		return spf_strlcpy(dst, field, lim);

	count = spf_split(spf_lengthof(part), part, field, delim, 0);

	if (spf_lengthof(part) <= count)
		goto toobig;

	if (rev) {
		for (i = 0, j = count - 1; i < j; i++, j--) {
			tmp     = part[i];
			part[i] = part[j];
			part[j] = tmp;
		}
	}

	if (keep && keep < count) {
		for (i = 0, j = count - keep; j < count; i++, j++)
			part[i] = part[j];

		count = keep;
	}

	for (i = 0; i < count; i++) {
		if (dp < lim)
			len = spf_strlcpy(&dst[dp], part[i], lim - dp);
		else
			len = strlen(part[i]);

		dp += len;

		if (dp < lim)
			dst[dp] = '.';

		++dp;
	}

	if (dp > 0)
		--dp;

	return dp;
toolong:
	*error = ENAMETOOLONG;

	return 0;
toobig:
	*error = E2BIG;

	return 0;
} /* spf_expand_() */


size_t spf_expand(char *dst, size_t lim, const char *src, const struct spf_env *env, int *error) {
	struct spf_sbuf macro;
	size_t len, dp = 0, sp = 0;

	*error = 0;

	do {
		while (src[sp] && src[sp] != '%') {
			if (dp < lim)
				dst[dp] = src[sp];
			++sp; ++dp;
		}

		if (!src[sp])
			break;

		switch (src[++sp]) {
		case '{':
			sbuf_init(&macro);

			while (src[++sp] && src[sp] != '}')
				sbuf_putc(&macro, src[sp]);

			if (src[sp] != '}')
				break;

			++sp;

			len = (dp < lim)
			    ? spf_expand_(&dst[dp], lim - dp, macro.str, env, error)
			    : spf_expand_(0, 0, macro.str, env, error);

			if (!len && *error)
				return 0;

			dp += len;

			break;
		default:
			if (dp < lim)
				dst[dp] = src[sp];
			++sp; ++dp;

			break;
		}
	} while (src[sp]);

	if (lim)
		dst[SPF_MIN(dp, lim - 1)] = '\0';

	return dp;
} /* spf_expand() */


_Bool spf_match(struct spf_term *term, const struct spf_env *env, int *error) {
	return 0;
} /* spf_match() */



struct spf_policy {
	struct spf_env env;

	SPF_HEAD(spf_rr) records;

	enum spf_result result;

	char qname[SPF_MAXDN + 1];
	enum spf_rr_type qtype;

	struct {
		char domain[SPF_MAXDN + 1];

		struct spf_rr *rr;
		struct spf_term *term;

		enum {
			SPF_S_QUERYRR,
			SPF_S_MECHANISMS,
			SPF_S_INCLUDE,
			SPF_S_MODIFIERS,
		} state;
	} stack[8], *frame;
}; /* struct spf_policy */


static struct spf_rr *spf_lookup(struct spf_policy *spf, const char *domain, enum spf_rr_type type) {
	char a[SPF_MAXDN + 1], b[SPF_MAXDN + 1];
	struct spf_rr *rr;

	spf_trim(a, domain, sizeof a, -1);
	spf_tolower(a);

	SPF_FOREACH(rr, &spf->records) {
		if (rr->qtype == type) {
			spf_trim(b, rr->qname, sizeof b, -1);
			spf_tolower(b);

			if (!strcmp(a, b))
				return rr;
		}
	}

	return 0;
} /* spf_lookup() */


static int spf_exec(struct spf_policy *spf) {
	int error;

exec:

	switch (spf->frame->state) {
	case SPF_S_QUERYRR:
		if (!(spf->frame->rr = spf_lookup(spf, spf->frame->domain, SPF_RR_SPF))) {
			spf->result = SPF_QUERYRR;

			spf_strlcpy(spf->qname, spf->frame->domain, sizeof spf->qname);
			spf->qtype = SPF_RR_SPF;

			return 0;
		}

		spf->frame->term = SPF_FIRST(&spf->frame->rr->spf.terms);

		spf->frame->state++;
	case SPF_S_MECHANISMS:
		while (spf->frame->term) {
			switch (spf->frame->term->type) {
			case SPF_ALL:
				break;
			case SPF_INCLUDE:
				break;
			case SPF_A:
				break;
			case SPF_MX:
				break;
			case SPF_PTR:
				break;
			case SPF_IP4:
				break;
			case SPF_IP6:
				break;
			case SPF_EXISTS:
				break;
			} /* switch() */
		}

		spf->result = SPF_NONE;

		break;
	case SPF_S_INCLUDE:
		break;
	default:
		assert(!"invalid SPF engine state");
	} /* switch(state) */

	if (spf->frame > spf->stack) {
		spf->frame--;

		spf_strlcpy(spf->env.d, spf->frame->domain, sizeof spf->env.d);

		goto exec;
	}

	return 0;
} /* spf_exec() */


struct spf_policy *spf_open(const struct spf_env *env, int *error) {
	struct spf_policy *spf = 0;

	if (!(spf = malloc(sizeof *spf)))
		goto syerr;

	spf->env = *env;

	SPF_INIT(&spf->records);

	memset(spf->stack, 0, sizeof spf->stack);

	spf->frame = &spf->stack[0];

	spf_strlcpy(spf->frame->domain, spf->env.d, sizeof spf->frame->domain);

	return spf;
syerr:
	*error = errno;

	free(spf);

	return 0;
} /* spf_open() */


void spf_close(struct spf_policy *spf) {
	struct spf_rr *rr;

	if (!spf)
		return;

	while ((rr = SPF_FIRST(&spf->records))) {
		SPF_REMOVE(&spf->records, rr);
		spf_rr_close(rr);
	}

	free(spf);
} /* spf_close() */


enum spf_result spf_check(struct spf_policy *spf, const char **qname, enum spf_rr_type *qtype, int *error) {
	if ((*error = spf_exec(spf)))
		return SPF_SYSFAIL;

	if (spf->result == SPF_QUERYRR) {
		*qname = spf->qname;
		*qtype = spf->qtype;
	} else
		*qname = 0;

	return spf->result;
} /* spf_check() */


void spf_addrr(struct spf_policy *spf, struct spf_rr *rr) {
	SPF_INSERT_HEAD(&spf->records, rr);
} /* spf_addrr() */


#if SPF_MAIN

#include <stdlib.h>
#include <stdio.h>

#include <string.h>

#include <unistd.h>	/* getopt(3) */


#define panic_(fn, ln, fmt, ...) \
	do { fprintf(stderr, fmt "%.1s", (fn), (ln), __VA_ARGS__); _Exit(EXIT_FAILURE); } while (0)

#define panic(...) panic_(__func__, __LINE__, "spf: (%s:%d) " __VA_ARGS__, "\n")


static int parse(const char *policy) {
	struct spf_rr *rr;
	int error;

	if (!(rr = spf_rr_open("25thandClement.com.", SPF_RR_SPF, &error)))
		panic("%s", strerror(error));

	if ((error = spf_rr_parse(rr, policy, strlen(policy))))
		panic("%s", strerror(error));

	spf_rr_close(rr);

	return 0;
} /* parse() */


static int expand(const char *src, const struct spf_env *env) {
	char dst[512];
	int error;

	if (!(spf_expand(dst, sizeof dst, src, env, &error)) && error)
		panic("%s: %s", src, strerror(error));	

	fprintf(stdout, "[%s]\n", dst);

	return 0;
} /* expand() */


static void ip_flags(int *flags, _Bool *libc, int argc, char *argv[]) {
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "nybble"))
			*flags |= SPF_6TOP_NYBBLE;
		else if (!strcmp(argv[i], "compat"))
			*flags |= SPF_6TOP_COMPAT;
		else if (!strcmp(argv[i], "mapped"))
			*flags |= SPF_6TOP_MAPPED;
		else if (!strcmp(argv[i], "mixed"))
			*flags |= SPF_6TOP_MIXED;
		else if (!strcmp(argv[i], "libc"))
			*libc = 1;
	}

	if (*libc && *flags)
		SPF_SAY("libc and nybble/compat/mapped are mutually exclusive");
	else if ((*flags & SPF_6TOP_NYBBLE) && (*flags & SPF_6TOP_MIXED))
		SPF_SAY("nybble and compat/mapped are mutually exclusive");
} /* ip_flags() */


#include <arpa/inet.h>

int ip6(int argc, char *argv[]) {
	struct in6_addr ip;
	char str[64];
	int ret, flags = 0;
	_Bool libc = 0;

	ip_flags(&flags, &libc, argc - 1, &argv[1]);

	memset(&ip, 0xff, sizeof ip);

	if (libc) {
		if (1 != (ret = inet_pton(AF_INET6, argv[0], &ip)))
			panic("%s: %s", argv[0], (ret == 0)? "not v6 address" : strerror(errno));

		inet_ntop(AF_INET6, &ip, str, sizeof str);
	} else {
		spf_pto6(&ip, argv[0]);
		spf_6top(str, sizeof str, &ip, flags);
	}

	puts(str);

	return 0;
} /* ip6() */


int ip4(int argc, char *argv[]) {
	struct in_addr ip;
	char str[16];
	int ret, flags = 0;
	_Bool libc = 0;

	ip_flags(&flags, &libc, argc - 1, &argv[1]);

	if (flags)
		SPF_SAY("nybble/compat/mapped invalid flags for v4 address");

	memset(&ip, 0xff, sizeof ip);

	if (libc) {
		if (1 != (ret = inet_pton(AF_INET, argv[0], &ip)))
			panic("%s: %s", argv[0], (ret == 0)? "not v4 address" : strerror(errno));

		inet_ntop(AF_INET, &ip, str, sizeof str);
	} else {
		spf_pto4(&ip, argv[0]);
		spf_4top(str, sizeof str, &ip);
	}

	puts(str);

	return 0;
} /* ip4() */



#define USAGE \
	"spf [-S:L:O:D:I:P:V:H:C:R:T:vh] parse <POLICY> | expand <MACRO> | ip6 <ADDR>\n" \
	"  -S EMAIL   <sender>\n" \
	"  -L LOCAL   local-part of <sender>\n" \
	"  -O DOMAIN  domain of <sender>\n" \
	"  -D DOMAIN  <domain>\n" \
	"  -I IP      <ip>\n" \
	"  -P DOMAIN  the validated domain name of <ip>\n" \
	"  -V STR     the string \"in-addr\" if <ip> is ipv4, or \"ip6\" if ipv6\n" \
	"  -H DOMAIN  HELO/EHLO domain\n" \
	"  -C IP      SMTP client IP\n" \
	"  -R DOMAIN  domain name of host performing the check\n" \
	"  -T TIME    current timestamp\n" \
	"  -v         be verbose\n" \
	"  -h         print usage\n" \
	"\n" \
	"Reports bugs to william@25thandClement.com\n"

int main(int argc, char **argv) {
	extern int optind;
	extern char *optarg;
	int opt;
	struct spf_env env;

	spf_debug = 1;

	memset(&env, 0, sizeof env);

	spf_strlcpy(env.p, "unknown", sizeof env.p);
	spf_strlcpy(env.r, "unknown", sizeof env.r);
	spf_itoa(env.t, sizeof env.t, (unsigned)time(0));

	while (-1 != (opt = getopt(argc, argv, "S:L:O:D:I:P:V:H:C:R:T:vh"))) {
		switch (opt) {
		case 'S':
			/* FALL THROUGH */
		case 'L':
			/* FALL THROUGH */
		case 'O':
			/* FALL THROUGH */
		case 'D':
			/* FALL THROUGH */
		case 'I':
			/* FALL THROUGH */
		case 'P':
			/* FALL THROUGH */
		case 'V':
			/* FALL THROUGH */
		case 'H':
			/* FALL THROUGH */
		case 'C':
			/* FALL THROUGH */
		case 'R':
			/* FALL THROUGH */
		case 'T':
			spf_set(&env, opt, optarg);

			break;
		case 'v':
			spf_debug++;

			break;
		case 'h':
			/* FALL THROUGH */
		default:
usage:
			fputs(USAGE, stderr);

			return (opt == 'h')? 0 : EXIT_FAILURE;
		} /* switch() */
	} /* while() */

	argc -= optind;
	argv += optind;

	if (!argc)
		goto usage;

	if (!strcmp(argv[0], "parse") && argc > 1) {
		return parse(argv[1]);
	} else if (!strcmp(argv[0], "expand") && argc > 1) {
		return expand(argv[1], &env);
	} else if (!strcmp(argv[0], "ip6") && argc > 1) {
		return ip6(argc - 1, &argv[1]);
	} else if (!strcmp(argv[0], "ip4") && argc > 1) {
		return ip4(argc - 1, &argv[1]);
	} else
		goto usage;

	return 0;
} /* main() */


#endif /* SPF_MAIN */
