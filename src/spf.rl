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

#include <errno.h>	/* EINVAL EFAULT ENAMETOOLONG E2BIG errno */

#include <assert.h>	/* assert(3) */

#include <time.h>	/* time(3) */

#include <setjmp.h>	/* jmp_buf setjmp(3) longjmp(3) */

#include <sys/socket.h>	/* AF_INET AF_INET6 */

#include <unistd.h>	/* gethostname(3) */

#include <netinet/in.h>	/* struct in_addr struct in6_addr */

#include "dns.h"
#include "spf.h"


#if SPF_DEBUG
#include <stdio.h> /* stderr fprintf(3) */

int spf_debug = SPF_DEBUG - 1;

#undef SPF_DEBUG
#define SPF_DEBUG(N) (spf_debug >= (N))

#define SPF_SAY_(fmt, ...) \
	do { if (SPF_DEBUG(1)) fprintf(stderr, fmt "%.1s", __func__, __LINE__, __VA_ARGS__); } while (0)
#define SPF_SAY(...) SPF_SAY_(">>>> (%s:%d) " __VA_ARGS__, "\n")
#define SPF_HAI SPF_SAY("HAI")

#define SPF_TRACE(retval, ...) ({ if (SPF_DEBUG(2)) SPF_SAY(__VA_ARGS__); (retval); })
#else
#undef SPF_DEBUG
#define SPF_DEBUG(N) 0

#define SPF_SAY(...)
#define SPF_HAI

#define SPF_TRACE(retval, ...) (retval)
#endif /* SPF_DEBUG */


#define spf_verify_true(R) (!!sizeof (struct { unsigned int constraint: (R)? 1 : -1; }))
#define spf_verify(R) extern int (*spf_contraint (void))[spf_verify_true(R)]

#define spf_lengthof(a) (sizeof (a) / sizeof (a)[0])
#define spf_endof(a) (&(a)[spf_lengthof((a))])

#define SPF_PASTE(x, y) a##b
#define SPF_XPASTE(x, y) SPF_PASTE(a, b)


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


/** domain normalization */

#define SPF_DN_CHOMP  1	/* discard root zone, if any */
#define SPF_DN_ANCHOR 2 /* add root zone, if none */
#define SPF_DN_TRUNC  4 /* discard sub-domain(s) if copy overflows */
#define SPF_DN_SUPER  8 /* discard sub-domain */

size_t spf_fixdn(char *dst, const char *src, size_t lim, int flags) {
	size_t op, dp, sp;
	int lc;

	sp = 0;
fixdn:
	op = sp;
	dp = 0;
	lc = 0;

	/* trim any leading dot(s) */
	while (src[sp] == '.') {
		if (!src[++sp]) /* but keep lone dot */
			{ --sp; break; }
	}

	while (src[sp]) {
		lc = src[sp];

		if (dp < lim)
			dst[dp] = src[sp];

		sp++; dp++;

		/* trim extra dot(s) */
		while (lc == '.' && src[sp] == '.')
			sp++;
	}

	if (flags & SPF_DN_CHOMP) {
		if (lc == '.')
			dp--;
	} else if (flags & SPF_DN_ANCHOR) {
		if (lc != '.') {
			if (dp < lim)
				dst[dp] = '.';

			dp++;
		}
	}

	if (flags & SPF_DN_SUPER) {
		flags &= ~SPF_DN_SUPER;

		while (src[op] == '.') {
			if (!src[++op]) {
				flags &= ~SPF_DN_ANCHOR;

				goto fixdn; /* output empty string */
			}
		}

		op += strcspn(&src[op], ".");

		if (src[op] == '.') {
			sp = op + 1;

			/** don't accidentally trim any final root zone. */
			if (!src[sp])
				sp--;
		}

		goto fixdn;
	} else if ((flags & SPF_DN_TRUNC) && dp >= lim) {
		op += strcspn(&src[op], ".");

		if (src[op] == '.') {
			sp = op + 1;

			if (src[sp])
				goto fixdn;

			/** return the minimum length possible */
		}
	}

	if (lim > 0)
		dst[SPF_MIN(dp, lim - 1)] = '\0';

	return dp;
} /* spf_fixdn() */


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


int spf_6cmp(const struct in6_addr *a, const struct in6_addr *b, unsigned prefix) {
	unsigned i, n;
	int cmp;

	for (i = 0; i < prefix / 8 && i < 16; i++) {
		if ((cmp = a->s6_addr[i] - b->s6_addr[i]))
			return cmp;
	}

	if ((prefix % 8) && i < 16) {
		n = (8 - (prefix % 8));

		if ((cmp = (a->s6_addr[i] >> n) - (b->s6_addr[i] >> n)))
			return cmp;
	}

	return 0;
} /* spf_6cmp() */


int spf_4cmp(const struct in_addr *a,  const struct in_addr *b, unsigned prefix) {
	unsigned long x = ntohl(a->s_addr), y = ntohl(b->s_addr);

	if (!prefix) {
		return 0;
	} if (prefix < 32) {
		x >>= 32 - (prefix % 32);
		y >>= 32 - (prefix % 32);
	}

	return (x < y)? -1 : (x > y)? 1 : 0;
} /* spf_4cmp() */


int spf_inetcmp(int af, const void *a, const void *b, unsigned prefix) {
	if (af == AF_INET6)
		return spf_6cmp(a, b, prefix);
	else
		return spf_4cmp(a, b, prefix);
} /* spf_inetcmp() */


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

static char *include_target(struct spf_include *inc) {
	return inc->domain;
} /* include_target() */


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
	return 0;
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

static char *mx_target(struct spf_mx *mx) {
	return mx->domain;
} /* mx_target() */


static const struct spf_ptr ptr_initializer =
	{ .type = SPF_PTR, .result = SPF_PASS, .domain = "%{d}" };

static void ptr_comp(struct spf_sbuf *sbuf, struct spf_ptr *ptr) {
	sbuf_putc(sbuf, ptr->result);
	sbuf_puts(sbuf, "ptr");
	sbuf_putc(sbuf, ':');
	sbuf_puts(sbuf, ptr->domain);
} /* ptr_comp() */

static char *ptr_target(struct spf_ptr *ptr) {
	return ptr->domain;
} /* ptr_target() */


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

static char *exists_target(struct spf_exists *exists) {
	return exists->domain;
} /* exists_target() */


static const struct spf_redirect redirect_initializer =
	{ .type = SPF_REDIRECT };

static void redirect_comp(struct spf_sbuf *sbuf, struct spf_redirect *redirect) {
	sbuf_puts(sbuf, "redirect");
	sbuf_putc(sbuf, '=');
	sbuf_puts(sbuf, redirect->domain);
} /* redirect_comp() */

static char *redirect_target(struct spf_redirect *redir) {
	return redir->domain;
} /* redirect_target() */


static const struct spf_exp exp_initializer =
	{ .type = SPF_EXP };

static void exp_comp(struct spf_sbuf *sbuf, struct spf_exp *exp) {
	sbuf_puts(sbuf, "exp");
	sbuf_putc(sbuf, '=');
	sbuf_puts(sbuf, exp->domain);
} /* exp_comp() */

static char *exp_target(struct spf_exp *exp) {
	return exp->domain;
} /* exp_target() */


static const struct spf_unknown unknown_initializer =
	{ .type = SPF_UNKNOWN };

static void unknown_comp(struct spf_sbuf *sbuf, struct spf_unknown *unknown) {
	sbuf_puts(sbuf, unknown->name);
	sbuf_putc(sbuf, '=');
	sbuf_puts(sbuf, unknown->value);
} /* unknown_comp() */


static char *no_target(struct spf_term *term) {
	return 0;
} /* no_target() */


static const struct {
	const void *initializer;
	size_t size;
	void (*comp)();
	_Bool (*match)();
	char *(*target)();
} spf_term[] = {
	[SPF_ALL]     = { &all_initializer, sizeof all_initializer, &all_comp, 0, &no_target },
	[SPF_INCLUDE] = { &include_initializer, sizeof include_initializer, &include_comp, 0, &include_target },
	[SPF_A]       = { &a_initializer, sizeof a_initializer, &a_comp, 0, &no_target },
	[SPF_MX]      = { &mx_initializer, sizeof mx_initializer, &mx_comp, 0, &mx_target },
	[SPF_PTR]     = { &ptr_initializer, sizeof ptr_initializer, &ptr_comp, 0, &ptr_target },
	[SPF_IP4]     = { &ip4_initializer, sizeof ip4_initializer, &ip4_comp, 0, &no_target },
	[SPF_IP6]     = { &ip6_initializer, sizeof ip6_initializer, &ip6_comp, 0, &no_target },
	[SPF_EXISTS]  = { &exists_initializer, sizeof exists_initializer, &exists_comp, 0, &exists_target },

	[SPF_REDIRECT] = { &redirect_initializer, sizeof redirect_initializer, &redirect_comp, 0, &redirect_target },
	[SPF_EXP]      = { &exp_initializer, sizeof exp_initializer, &exp_comp, 0, &exp_target },
	[SPF_UNKNOWN]  = { &unknown_initializer, sizeof unknown_initializer, &unknown_comp, 0, &no_target },
}; /* spf_term[] */

static char *term_comp(struct spf_sbuf *sbuf, void *term) {
	spf_term[((struct spf_term *)term)->type].comp(sbuf, term);

	return sbuf->str;
} /* term_comp() */

static char *term_target(void *term) {
	return spf_term[((struct spf_term *)term)->type].target(term);
} /* term_target() */


%%{
	machine spf_grammar;
	alphtype unsigned char;

	action oops {
		const unsigned char *part;

		rr->error.lc = fc;

		if (p - (unsigned char *)rdata >= (sizeof rr->error.near / 2))
			part = p - (sizeof rr->error.near / 2);
		else
			part = rdata;

		memset(rr->error.near, 0, sizeof rr->error.near);
		memcpy(rr->error.near, part, SPF_MIN(sizeof rr->error.near - 1, pe - part));

		if (SPF_DEBUG(1)) {
			if (isgraph(rr->error.lc))
				SPF_SAY("`%c' invalid near `%s'", rr->error.lc, rr->error.near);
			else
				SPF_SAY("error near `%s'", rr->error.near);
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

	action term_macro {
		term.macros |= 1U << ((tolower((unsigned char)fc)) - 'a');
	}

	action term_end {
		if (term.type) {
			struct spf_term *tmp;

			SPF_TRACE(0, "term -> %s", term_comp(&(struct spf_sbuf){ 0 }, &term));

			if (!(tmp = malloc(sizeof *tmp)))
				{ error = errno; goto error; }

			*tmp = term;

			SPF_LIST_INSERT_TAIL(&rr->terms, tmp);
			rr->count++;
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
			spf_fixdn(term.include.domain, domain.str, sizeof term.include.domain, SPF_DN_TRUNC);
	}

	action a_begin {
		term.a      = a_initializer;
		term.result = result;
	}

	action a_end {
		if (*domain.str)
			spf_fixdn(term.a.domain, domain.str, sizeof term.a.domain, SPF_DN_TRUNC);

		term.a.prefix4 = prefix4;
		term.a.prefix6 = prefix6;
	}

	action mx_begin {
		term.mx    = mx_initializer;
		term.result = result;
	}

	action mx_end {
		if (*domain.str)
			spf_fixdn(term.mx.domain, domain.str, sizeof term.mx.domain, SPF_DN_TRUNC);

		term.mx.prefix4 = prefix4;
		term.mx.prefix6 = prefix6;
	}

	action ptr_begin {
		term.ptr    = ptr_initializer;
		term.result = result;
	}

	action ptr_end {
		if (*domain.str)
			spf_fixdn(term.ptr.domain, domain.str, sizeof term.ptr.domain, SPF_DN_TRUNC);
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
			spf_fixdn(term.exists.domain, domain.str, sizeof term.exists.domain, SPF_DN_TRUNC);
	}

	action redirect_begin {
		term.redirect = redirect_initializer;
	}

	action redirect_end {
		if (*domain.str)
			spf_fixdn(term.redirect.domain, domain.str, sizeof term.redirect.domain, SPF_DN_TRUNC);
	}

	action exp_begin {
		term.exp = exp_initializer;
	}

	action exp_end {
		if (*domain.str)
			spf_fixdn(term.exp.domain, domain.str, sizeof term.exp.domain, SPF_DN_TRUNC);
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

	macro_letter  = ("s"i | "l"i | "o"i | "d"i | "i"i | "p"i | "v"i | "h"i | "c"i | "r"i | "t"i) $term_macro;
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


int spf_rr_parse(struct spf_rr *rr, const void *rdata, size_t rdlen) {
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
} /* spf_rr_parse() */


void spf_rr_init(struct spf_rr *rr) {
	memset(rr, 0, sizeof *rr);
	SPF_LIST_INIT(&rr->terms);
} /* spf_rr_init() */


void spf_rr_reset(struct spf_rr *rr) {
	struct spf_term *term;

	while (SPF_LIST_END(&rr->terms) != (term = SPF_LIST_FIRST(&rr->terms))) {
		SPF_LIST_REMOVE(&rr->terms, term);
		free(term);
	}

	spf_rr_init(rr);
} /* spf_rr_reset() */


int spf_env_init(struct spf_env *env, int af, const void *ip, const char *domain, const char *sender) {
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

	spf_strlcpy(env->r, "unknown", sizeof env->r);

	spf_itoa(env->t, sizeof env->t, (unsigned long)time(0));

	return 0;
} /* spf_env_init() */


static size_t spf_env_get_(char **field, int which, struct spf_env *env) {
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
} /* spf_env_get_() */


size_t spf_env_get(char *dst, size_t lim, int which, const struct spf_env *env) {
	char *src;

	if (!spf_env_get_(&src, which, (struct spf_env *)env))
		return 0;

	return spf_strlcpy(dst, src, lim);
} /* spf_env_get() */


size_t spf_env_set(struct spf_env *env, int which, const char *src) {
	size_t lim, len;
	char *dst;

	if (!(lim = spf_env_get_(&dst, which, (struct spf_env *)env)))
		return strlen(src);

	len = spf_strlcpy(dst, src, lim);

	return SPF_MIN(lim - 1, len);
} /* spf_env_set() */


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

	if (!(len = spf_env_get(field, sizeof field, macro, env)))
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


size_t spf_expand(char *dst, size_t lim, spf_macros_t *macros, const char *src, const struct spf_env *env, int *error) {
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

			if (isalpha((unsigned char)*macro.str))
				*macros |= 1U << (tolower((unsigned char)*macro.str) - 'a');

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


_Bool spf_used(spf_macros_t macros, int which) {
	if (!isalpha((unsigned char)which))
		return 0;

	return !!(macros & (1U << (tolower((unsigned char)which) - 'a')));
} /* spf_used() */


spf_macros_t spf_macros(const char *src, const struct spf_env *env) {
	spf_macros_t macros = 0;
	int error;

	spf_expand(0, 0, &macros, src, env, &error);

	return macros;
} /* spf_macros() */


enum vm_type {
	T_NIL,
	T_INT = 0x01,
	T_PTR = 0x02,
	T_MEM = 0x04,

	T_ANY = T_INT|T_PTR|T_MEM,
}; /* enum vm_type */

enum vm_opcode {
	OP_HALT,	/* 0/0 */

	OP_PC,		/* 0/1 Push vm.pc */
	OP_CALL,	/* 2/N */

	OP_TRUE,	/* 0/1 Push true. */
	OP_FALSE,	/* 0/1 Push false. */
	OP_ZERO,	/* 0/1 Push zero. */
	OP_ONE,		/* 0/1 Push 1 */
	OP_TWO,		/* 0/1 Push 2 */
	OP_THREE,	/* 0/1 Push 3 */
	OP_I8,		/* 0/1 Decode next op and push as T_INT */ 
	OP_I16,		/* 0/1 Decode next 2 ops and push as T_INT */ 
	OP_I32,		/* 0/1 Decode next 4 ops and push as T_INT */
	OP_PTR,		/* 0/1 Decode next sizeof(intptr_t) opts and push as T_PTR */
	OP_MEM,		/* 0/1 Decode next sizeof(intptr_t) ops and push as T_MEM */

	OP_DEC,		/* 1/1 Decrement S(-1) */
	OP_INC,		/* 1/1 Increment S(-1) */
	OP_NEG,		/* 1/1 Arithmetically negate S(-1) (changes type to T_INT) */
	OP_ADD,		/* 2/1 Push S(-2) + S(-1). */
	OP_NOT,		/* 1/1 Logically Negate S(-1) (changes type to T_INT)  */

	OP_JMP,		/* 2/0 If S(-2) is non-zero, jump S(-1) instruction */
	OP_GOTO,	/* 2/0 If S(-2) is non-zero, goto I(S(-1)) */

	OP_POP,		/* 0/0 Pop item from stack */
	OP_LOAD,	/* 1/1 Push a copy of S(S(-1)) onto stack (changes T_MEM to T_PTR) */
	OP_STORE,	/* 2/0 Pop index and item and store at index (index computed after popping). */
	OP_MOVE,	/* 1/1 Move S(S(-1)) to top of stack, shifting everything else down. */
	OP_SWAP,	/* 0/0 Swap top two items. */

	OP_EXPAND,	/* 1/1 Push spf_expand(S(-1)). */
	OP_HASVAR,	/* 2/1 */

	OP_SUBMIT,	/* 2/0 dns_res_submit(). in: 2(qtype, qname) out: 0 */
	OP_FETCH,	/* 0/1 dns_res_fetch(). in: 0 out: 1(struct dns_packet) */
	OP_QNAME,	/* 1/1 Pop packet, Push QNAME. */
	OP_GREP,	/* 3/1 Push iterator. Takes QNAME, section and type. */
	OP_NEXT,	/* 1/2 Push next stringized RR data. */

	OP_VERIFY,	/* 1/0 */

	OP_REVMAP,

	OP_ALL      = SPF_ALL,
	OP_INCLUDE  = SPF_INCLUDE,
	OP_A        = SPF_A,
	OP_MX       = SPF_MX,
	OP_PTR_     = SPF_PTR,
	OP_IP4      = SPF_IP4,
	OP_IP6      = SPF_IP6,
	OP_EXISTS   = SPF_EXISTS,

	OP_REDIRECT = SPF_REDIRECT,
	OP_EXP      = SPF_EXP,

	OP__COUNT,
}; /* enum vm_opcode */

#define op_sizeof(opcode) op_size[(opcode)];

static const int op_size[OP__COUNT] = {
	[0 ... OP__COUNT - 1] = 1,
	[OP_I8]  = 2,
	[OP_I16] = 3,
	[OP_I32] = 5,
	[OP_PTR] = 1 + sizeof (uintptr_t),
	[OP_MEM] = 1 + sizeof (uintptr_t),
};


#define SPF_CODE_MAX 256
#define SPF_STACK_MAX 64

struct spf_vm {
	unsigned code[SPF_CODE_MAX];
	unsigned pc, end;
	struct {
		unsigned revmap, exp;
	} sub;

	unsigned char type[SPF_STACK_MAX];
	intptr_t stack[SPF_STACK_MAX];
	unsigned sp;
}; /* struct spf_vm */


struct spf_resolver {
	struct spf_env *env;

	struct spf_vm vm;

	jmp_buf *trap;

	struct dns_resolver *res;
	union {
		struct dns_packet ptr;
		char pbuf[dns_p_calcsize(512)];
	};

	enum spf_result result;
	struct spf_sbuf sbuf;
}; /* struct spf_resolver */


#define SPF_VAR_REVMAP 0

static void vm_initvars(struct spf_resolver *spf) {
	/* 0(SPF_VAR_REVMAP) */
	spf->vm.type[spf->vm.sp]  = T_INT;
	spf->vm.stack[spf->vm.sp] = 0;
	spf->vm.sp++;
} /* vm_initvars() */


static void vm_throw(struct spf_resolver *spf, int error) {
	longjmp(*spf->trap, (error)? error : EINVAL);
} /* vm_throw() */

static void vm_assert(struct spf_resolver *spf, int cond, int error) {
	if (!cond)
		vm_throw(spf, error);
} /* vm_assert() */

static void vm_extend(struct spf_resolver *spf, unsigned n) {
	vm_assert(spf, spf_lengthof(spf->vm.stack) - spf->vm.sp >= n, EFAULT);
} /* vm_extend() */


static int vm_indexof(struct spf_resolver *spf, int p) {
	if (p < 0)
		p = spf->vm.sp + p;

	vm_assert(spf, p >= 0 && p < spf->vm.sp, EFAULT);

	return p;
} /* vm_indexof() */


static enum vm_type vm_typeof(struct spf_resolver *spf, int p) {
	return spf->vm.type[vm_indexof(spf, p)];
} /* vm_typeof() */


static void t_free(struct spf_resolver *spf, enum vm_type t, intptr_t v) {
	switch (t) {
	case T_MEM:
		free((void *)v);

		break;
	default:
		vm_throw(spf, EFAULT);
	} /* switch() */
} /* t_free() */


static intptr_t vm_pop(struct spf_resolver *spf, enum vm_type t) {
	intptr_t v;
	vm_assert(spf, spf->vm.sp, EFAULT);
	spf->vm.sp--;
	vm_assert(spf, (spf->vm.type[spf->vm.sp] & t), EINVAL);
	t = spf->vm.type[spf->vm.sp];
	v = spf->vm.stack[spf->vm.sp];
	t_free(spf, t, v);
	spf->vm.type[spf->vm.sp]  = T_NIL;
	spf->vm.stack[spf->vm.sp] = 0;
	return v;
} /* vm_pop() */


static void vm_discard(struct spf_resolver *spf, unsigned n) {
	vm_assert(spf, n <= spf->vm.sp, EFAULT);
	while (n--)
		vm_pop(spf, T_ANY);
} /* vm_discard() */


static intptr_t vm_push(struct spf_resolver *spf, enum vm_type t, intptr_t v) {
	vm_assert(spf, spf->vm.sp < spf_lengthof(spf->vm.stack), ENOMEM);

	spf->vm.type[spf->vm.sp] = t;
	spf->vm.stack[spf->vm.sp] = v;

	spf->vm.sp++;

	return v;
} /* vm_push() */


#define vm_swap(spf) vm_move((spf), -2)

static intptr_t vm_move(struct spf_resolver *spf, int p) {
	enum vm_type t;
	intptr_t v;
	int i;

	p = vm_indexof(spf, p);
	t = spf->vm.type[p];
	v = spf->vm.stack[p];

	i = p;

	/*
	 * DO NOT move a T_MEM item over an equivalent T_PTR, because that
	 * breaks garbage-collection. Instead, swap types with the first
	 * equivalent T_PTR found. (WARNING: This breaks if T_PTR points
	 * into a T_MEM object. Just don't do that--nest pointers and swap
	 * stack positions.)
	 */
	if (v == T_MEM) {
		for (; i < spf->vm.sp - 1; i++) {
			if (spf->vm.type[i + 1] == T_PTR && spf->vm.stack[i + 1] == v) {
				spf->vm.type[i + 1] = T_MEM;
				t = T_PTR;

				break;
			}

			spf->vm.type[i]  = spf->vm.type[i + 1];
			spf->vm.stack[i] = spf->vm.stack[i + 1];
		}
	}

	for (; i < spf->vm.sp - 1; i++) {
		spf->vm.type[i]  = spf->vm.type[i + 1];
		spf->vm.stack[i] = spf->vm.stack[i + 1];
	}

	spf->vm.type[i]  = t;
	spf->vm.stack[i] = v;

	return v;
} /* vm_move() */


static intptr_t vm_strdup(struct spf_resolver *spf, void *s) {
	void *v;

	vm_extend(spf, 1);
	v = strdup(s);
	vm_assert(spf, !!v, errno);
	vm_push(spf, T_MEM, (intptr_t)v);

	return (intptr_t)v;
} /* vm_strdup() */


static intptr_t vm_memdup(struct spf_resolver *spf, void *p, size_t len) {
	void *v;

	vm_extend(spf, 1);
	v = malloc(len);
	vm_assert(spf, !!v, errno);
	memcpy(v, p, len);
	vm_push(spf, T_MEM, (intptr_t)v);

	return (intptr_t)v;
} /* vm_memdup() */


static intptr_t vm_peek(struct spf_resolver *spf, int p, enum vm_type t) {
	p = vm_indexof(spf, p);
	vm_assert(spf, t & vm_typeof(spf, p), EINVAL);
	return spf->vm.stack[p];
} /* vm_peek() */


static intptr_t vm_poke(struct spf_resolver *spf, int p, enum vm_type t, intptr_t v) {
	p = vm_indexof(spf, p);
	t_free(spf, spf->vm.type[p], spf->vm.stack[p]);
	spf->vm.type[p]  = t;
	spf->vm.stack[p] = v;
	return v;
} /* vm_poke() */


#define vm_emit_(spf, code, v, ...) vm_emit((spf), (code), (v))
#define vm_emit(spf, ...) vm_emit_((spf), __VA_ARGS__, 0)

static unsigned (vm_emit)(struct spf_resolver *spf, enum vm_opcode code, intptr_t v_) {
	uintptr_t v;
	unsigned i, n;

	vm_assert(spf, spf->vm.end < spf_lengthof(spf->vm.code), ENOMEM);

	spf->vm.code[spf->vm.end] = code;

	switch (code) {
	case OP_I8:
		n = 1; goto copy;
	case OP_I16:
		n = 2; goto copy;
	case OP_I32:
		n = 4; goto copy;
	case OP_PTR:
		/* FALL THROUGH */
	case OP_MEM:
		n = sizeof (uintptr_t);
copy:
		v = (uintptr_t)v_;
		vm_assert(spf, spf->vm.end <= spf_lengthof(spf->vm.code) - n, ENOMEM);

		for (i = 0; i < n; i++)
			spf->vm.code[++spf->vm.end] = 0xffU & (v >> (8U * ((n-i)-1)));

		break;
	default:
		break;
	} /* switch() */

	return spf->vm.end++;
} /* vm_emit() */


static void vm_emit_revmap(struct spf_resolver *spf) {
	if (spf->vm.sub.revmap && spf->vm.sub.revmap < spf->vm.end)
		return;

	/*
	 * REVMAP subroutine. Expects return address at top of stack.
	 * Returns nothing.
	 */
	spf->vm.sub.revmap = spf->vm.end;

	/*
	 * Check SPF_VAR_REVMAP. If TRUE then just return; we've already
	 * completed this work.
	 */
	vm_emit(spf, OP_I8, SPF_VAR_REVMAP);
	vm_emit(spf, OP_LOAD);
	vm_emit(spf, OP_NOT);
	vm_emit(spf, OP_I8, 4);
	vm_emit(spf, OP_JMP);   /* jump to body if !SPF_VAR_REVMAP */
	vm_emit(spf, OP_TRUE);  /* conditional */
	vm_emit(spf, OP_SWAP);  /* swap conditional and address */
	vm_emit(spf, OP_GOTO);
	/* #ops = 10 */

	/*
	 * REVMAP begin.
	 */
	vm_emit(spf, OP_PTR, (intptr_t)"%{ir}.%{v}.arpa.");
	vm_emit(spf, OP_EXPAND);
	vm_emit(spf, OP_I8, DNS_T_PTR);
	vm_emit(spf, OP_SUBMIT);
	vm_emit(spf, OP_FETCH);
	vm_emit(spf, OP_QNAME);
	vm_emit(spf, OP_I8, DNS_S_AN);
	vm_emit(spf, OP_I8, DNS_T_PTR);
	vm_emit(spf, OP_GREP);
	/* #ops = OP_PTR + 11 */

	/*
	 * REVMAP loop. At this point we have three items on the stack.
	 * 	[-3] return address
	 * 	[-2] DNS packet
	 * 	[-1] grep iterator
	 */
	vm_emit(spf, OP_NEXT);
	vm_emit(spf, OP_ONE);
	vm_emit(spf, OP_NEG);
	vm_emit(spf, OP_LOAD);
	vm_emit(spf, OP_NOT);
	vm_emit(spf, OP_I8, 11); /* distance from epilog */
	vm_emit(spf, OP_JMP);
	/* #ops = 8 */

	/*
	 * REVMAP loop body.
	 * 	[-4] return address
	 * 	[-3] DNS packet
	 * 	[-2] grep iterator
	 * 	[-1] rdata
	 */ 
	vm_emit(spf, OP_I8, DNS_T_A);
	vm_emit(spf, OP_SUBMIT);
	vm_emit(spf, OP_FETCH);
	vm_emit(spf, OP_VERIFY);
	vm_emit(spf, OP_POP);
	vm_emit(spf, OP_TRUE);
	vm_emit(spf, OP_I8, 18); /* distance from beginning of loop  */
	vm_emit(spf, OP_NEG);    /* jump backwards */
	vm_emit(spf, OP_JMP);
	/* #ops = 11 */

	/*
	 * REVMAP epilog
	 * 	[-4] return address
	 * 	[-3] DNS packet
	 * 	[-2] grep iterator
	 * 	[-1] rdata
	 */
	vm_emit(spf, OP_POP);   /* pop rdata */
	vm_emit(spf, OP_POP);   /* pop iterator */
	vm_emit(spf, OP_POP);   /* pop packet */
	vm_emit(spf, OP_TRUE);
	vm_emit(spf, OP_I8, SPF_VAR_REVMAP);
	vm_emit(spf, OP_STORE);
	vm_emit(spf, OP_TRUE);  /* conditional */
	vm_emit(spf, OP_SWAP);  /* swap conditional and address */
	vm_emit(spf, OP_GOTO);
	/* #ops = 10 */
} /* vm_emit_revmap() */


static void vm_emit_exp(struct spf_resolver *spf) {
	if (spf->vm.sub.exp && spf->vm.sub.exp < spf->vm.end)
		return;

	/*
	 * EXP subroutine.
	 */
	spf->vm.sub.exp = spf->vm.end;

	/*
	 * EXP begin.
	 * 	[-2] return address
	 * 	[-1] target domain
	 */
	vm_emit(spf, OP_I8, 'p');
	vm_emit(spf, OP_HASVAR);
	vm_emit(spf, OP_NOT);
	vm_emit(spf, OP_TWO);
	vm_emit(spf, OP_JMP);
	vm_emit(spf, OP_REVMAP);
	vm_emit(spf, OP_EXPAND);
	vm_emit(spf, OP_I8, DNS_T_TXT);
	vm_emit(spf, OP_SUBMIT);
	vm_emit(spf, OP_FETCH);	/* [-2] return [-1] packet */
	vm_emit(spf, OP_QNAME);
	vm_emit(spf, OP_I8, DNS_S_AN);
	vm_emit(spf, OP_I8, DNS_T_TXT);
	vm_emit(spf, OP_GREP); /* [-3] return [-2] packet [-1] iterator */
	vm_emit(spf, OP_NEXT); /* [-4] return [-3] packet [-2] iterator [-1] txt */
	vm_emit(spf, OP_SWAP);
	vm_emit(spf, OP_POP);  /* [-3] return [-2] packet [-1] txt */
	vm_emit(spf, OP_SWAP);
	vm_emit(spf, OP_POP);  /* [-2] return [-1] txt */
	vm_emit(spf, OP_I8, 'p');
	vm_emit(spf, OP_HASVAR);
	vm_emit(spf, OP_TWO);
	vm_emit(spf, OP_NOT);
	vm_emit(spf, OP_JMP);
	vm_emit(spf, OP_REVMAP);
	vm_emit(spf, OP_EXPAND);
	vm_emit(spf, OP_SWAP);
	vm_emit(spf, OP_TRUE);
	vm_emit(spf, OP_SWAP);
	vm_emit(spf, OP_GOTO);
} /* vm_emit_exp() */


static void vm_emit_check(struct spf_resolver *spf, struct spf_rr *rr) {
	struct spf_term *term, *redir, *exp;
	int pc, error;

	pc    = spf->vm.end++;
	redir = 0;
	exp   = 0;

	SPF_LIST_FOREACH(term, &rr->terms) {
		switch (term->type) {
		case SPF_EXP:
			exp = term;

			break;
		case SPF_REDIRECT:
			redir = term;

			break;
		default:
			break;
		} /* switch() */
	}

	SPF_LIST_FOREACH(term, &rr->terms) {
		if (!SPF_ISMECHANISM(term->type))
			continue;

		if (spf_used(term->macros, 'p') || term->type == SPF_PTR)
			vm_emit(spf, OP_REVMAP);

		vm_emit(spf, OP_PTR, (intptr_t)term);
		vm_emit(spf, term->type);
	} /* SPF_LIST_FOREACH() */

	if (redir) {
		if (spf_used(redir->macros, 'p'))
			vm_emit_revmap(spf);

		vm_emit(spf, OP_PTR, (intptr_t)redir);
		vm_emit(spf, SPF_REDIRECT);
	}

	if (exp)
		;;
} /* vm_emit_check() */


static void vm_comptxt(struct spf_resolver *spf, const void *txt, size_t len) {
	struct spf_rr rr;
	struct spf_term *term, *redir, *exp;
	int ip, error;

	spf_rr_init(&rr);

	if (len < sizeof "v=spf1" || memcmp(txt, "v=spf1", sizeof "v=spf1" - 1))
		vm_throw(spf, EINVAL);

	if ((error = spf_rr_parse(&rr, txt, len)))
		vm_throw(spf, error);
} /* vm_comptxt() */


static void op_pop(struct spf_resolver *spf, enum vm_opcode code) {
	vm_pop(spf, T_ANY);
	spf->vm.pc++;
} /* op_pop() */


static void op_load(struct spf_resolver *spf, enum vm_opcode code) {
	int p, t;

	p = vm_pop(spf, T_INT);
	t = vm_typeof(spf, p);

	/* convert memory to pointer to prevent double free's */
	vm_push(spf, (t & (T_MEM))? T_PTR : t, vm_peek(spf, p, T_ANY));
} /* op_load() */


static void op_store(struct spf_resolver *spf, enum vm_opcode code) {
	int p, t;
	intptr_t v;
	p = vm_indexof(spf, vm_pop(spf, T_INT));
	v = vm_pop(spf, T_INT); /* restrict to T_INT so we don't have to worry about GC. */
	vm_poke(spf, p, T_INT, v);
	spf->vm.pc++;
} /* op_store() */


static void op_move(struct spf_resolver *spf, enum vm_opcode code) {
	vm_move(spf, vm_pop(spf, T_INT));
} /* op_move() */


static void op_swap(struct spf_resolver *spf, enum vm_opcode code) {
	vm_swap(spf);
} /* op_swap() */


static void op_jmp(struct spf_resolver *spf, enum vm_opcode code) {
	intptr_t cond = vm_peek(spf, -2, T_ANY);
 	int pc = spf->vm.pc + vm_peek(spf, -1, T_INT);

	vm_discard(spf, 2);

	if (cond) {
		vm_assert(spf, pc >= 0 && pc < spf->vm.end, EFAULT);
		spf->vm.pc = pc;
	} else
		spf->vm.pc++;
} /* op_jmp() */


static void op_goto(struct spf_resolver *spf, enum vm_opcode code) {
	intptr_t cond = vm_peek(spf, -2, T_ANY);
 	int pc = vm_peek(spf, -1, T_INT);

	vm_discard(spf, 2);

	if (cond) {
		vm_assert(spf, pc >= 0 && pc < spf->vm.end, EFAULT);
		spf->vm.pc = pc;
	} else
		spf->vm.pc++;
} /* op_goto() */


static void op_call(struct spf_resolver *spf, enum vm_opcode code) {
	int f, n, i;

	f = vm_pop(spf, T_INT);
	n = vm_pop(spf, T_INT);

	vm_push(spf, T_INT, spf->vm.pc + 1);

	/* swap return address with parameters */
	for (i = 0; i < n; i++)
		vm_move(spf, -(n + 1));

	spf->vm.pc = f;
} /* op_call() */


static void op_pc(struct spf_resolver *spf, enum vm_opcode code) {
	vm_push(spf, T_INT, spf->vm.pc);
	spf->vm.pc++;
} /* op_pc() */


static void op_const(struct spf_resolver *spf, enum vm_opcode code) {
	intptr_t v;

	switch (code) {
	case OP_TRUE: case OP_FALSE:
		v = (code == OP_TRUE);
		break;
	case OP_ZERO: case OP_ONE: case OP_TWO: case OP_THREE:
		v = (code - OP_ZERO);
		break;
	default:
		vm_assert(spf, 0, EFAULT);
	} /* switch() */

	vm_push(spf, T_INT, v);
	spf->vm.pc++;
} /* op_const() */


static void op_var(struct spf_resolver *spf, enum vm_opcode code) {
	uintptr_t v;
	enum vm_type t;
	int i, n;

	switch (code) {
	case OP_I8:
		n = 1;
		t = T_INT;
		break;
	case OP_I16:
		n = 2;
		t = T_INT;
		break;
	case OP_I32:
		n = 4;
		t = T_INT;
		break;
	case OP_PTR:
		n = sizeof (uintptr_t);
		t = T_PTR;
		break;
	case OP_MEM:
		n = sizeof (uintptr_t);
		t = T_MEM;
		break;
	default:
		vm_assert(spf, 0, EINVAL);
	} /* switch () */

	v = 0;

	for (i = 0; i < n; i++) {
		vm_assert(spf, ++spf->vm.pc < spf->vm.end, EFAULT);
		v <<= 8;
		v |= 0xff & spf->vm.code[spf->vm.pc];
	}

	vm_push(spf, t, (intptr_t)v);

	spf->vm.pc++;
} /* op_var() */


static void op_dec(struct spf_resolver *spf, enum vm_opcode code) {
	vm_poke(spf, -1, T_INT, vm_peek(spf, -1, T_INT) - 1);
} /* op_dec() */


static void op_inc(struct spf_resolver *spf, enum vm_opcode code) {
	vm_poke(spf, -1, T_INT, vm_peek(spf, -1, T_INT) + 1);
} /* op_inc() */


static void op_neg(struct spf_resolver *spf, enum vm_opcode code) {
	vm_poke(spf, -1, T_INT, -vm_peek(spf, -1, T_ANY));
} /* op_neg() */


static void op_add(struct spf_resolver *spf, enum vm_opcode code) {
	vm_push(spf, T_INT, vm_pop(spf, T_INT) + vm_pop(spf, T_INT));
} /* op_add() */


static void op_not(struct spf_resolver *spf, enum vm_opcode code) {
	vm_poke(spf, -1, T_INT, !vm_peek(spf, -1, T_ANY));
} /* op_not() */


static void op_submit(struct spf_resolver *spf, enum vm_opcode code) {
	void *qname = (void *)vm_peek(spf, -2, T_PTR|T_MEM);
	int qtype   = vm_peek(spf, -1, T_INT);
	int error;

	error = dns_res_submit(spf->res, qname, qtype, DNS_C_IN);
	vm_assert(spf, !error, error);

	vm_discard(spf, 2);

	spf->vm.pc++;
} /* op_submit() */


static void op_fetch(struct spf_resolver *spf, enum vm_opcode code) {
	struct dns_packet *pkt;
	int error;

	error = dns_res_check(spf->res);
	vm_assert(spf, !error, error);

	vm_extend(spf, 1);
	pkt = dns_res_fetch(spf->res, &error);
	vm_assert(spf, !!pkt, error);
	vm_push(spf, T_MEM, (intptr_t)pkt);

	spf->vm.pc++;
} /* op_fetch() */


static void op_qname(struct spf_resolver *spf, enum vm_opcode code) {
	struct dns_packet *pkt;
	char qname[DNS_D_MAXNAME + 1];
	int error;

	pkt = (void *)vm_peek(spf, -1, T_PTR|T_MEM);

	if (!dns_d_expand(qname, sizeof qname, 12, pkt, &error))
		vm_throw(spf, error);

	vm_pop(spf, T_ANY);
	vm_strdup(spf, qname);

	spf->vm.pc++;
} /* op_qname() */


struct vm_grep {
	struct dns_rr_i iterator;
	char name[DNS_D_MAXNAME + 1];
}; /* struct vm_grep */

static void op_grep(struct spf_resolver *spf, enum vm_opcode code) {
	struct dns_packet *pkt;
	char *name;
	struct vm_grep *grep;
	int sec, type, error;

	pkt  = (void *)vm_peek(spf, -4, T_PTR|T_MEM);
	name = (void *)vm_peek(spf, -3, T_PTR|T_MEM);
	sec  = vm_peek(spf, -2, T_INT);
	type = vm_peek(spf, -1, T_INT);

	if (!(grep = malloc(sizeof *grep)))
		vm_throw(spf, errno);

	memset(&grep->iterator, 0, sizeof grep->iterator);
	spf_strlcpy(grep->name, name, sizeof grep->name);

	grep->iterator.name    = name;
	grep->iterator.section = sec;
	grep->iterator.type    = type;
	dns_rr_i_init(&grep->iterator, pkt);

	vm_discard(spf, 3);
	vm_push(spf, T_MEM, (intptr_t)grep);

	spf->vm.pc++;
} /* op_grep() */


static void op_next(struct spf_resolver *spf, enum vm_opcode code) {
	struct dns_packet *pkt;
	struct vm_grep *grep;
	struct dns_rr rr;
	int error;

	pkt  = (void *)vm_peek(spf, -2, T_PTR|T_MEM);
	grep = (void *)vm_peek(spf, -1, T_PTR|T_MEM);

	if (dns_rr_grep(&rr, 1, &grep->iterator, pkt, &error)) {
		union dns_any any;
		char rd[DNS_D_MAXNAME + 1];

		if ((error = dns_any_parse(&any, &rr, pkt)))
			vm_throw(spf, error);

		if (!dns_any_print(rd, sizeof rd, &any, rr.type))
			goto none;

		vm_pop(spf, T_ANY);
		vm_strdup(spf, rd);
	} else {
none:
		vm_pop(spf, T_ANY);
		vm_push(spf, T_NIL, 0);
	}

	spf->vm.pc++;
} /* op_next() */


static void op_expand(struct spf_resolver *spf, enum vm_opcode code) {
	spf_macros_t macros = 0;
	char dst[512];
	int error;

	if (!spf_expand(dst, sizeof dst, &macros, (void *)vm_peek(spf, -1, T_PTR|T_MEM), spf->env, &error))
		vm_throw(spf, error);

	vm_pop(spf, T_ANY);
	vm_strdup(spf, dst);

	spf->vm.pc++;
} /* op_expand() */


static void op_hasvar(struct spf_resolver *spf, enum vm_opcode code) {
	spf_macros_t macros = 0;
	int error, macro;

	if (!spf_expand(0, 0, &macros, (void *)vm_peek(spf, -2, T_PTR|T_MEM), spf->env, &error))
		vm_throw(spf, error);

	vm_push(spf, T_INT, !!spf_used(macros, vm_pop(spf, T_INT)));

	spf->vm.pc++;
} /* op_hasvar() */


static void op_verify(struct spf_resolver *spf, enum vm_opcode code) {
	struct dns_packet *pkt;
	char qname[DNS_D_MAXNAME + 1], dn[DNS_D_MAXNAME + 1];
	struct dns_rr rr;
	struct in_addr a, b;
	int error;

	pkt = (void *)vm_peek(spf, -1, T_PTR|T_MEM);

	if (!dns_d_expand(qname, sizeof qname, 12, pkt, &error))
		vm_throw(spf, error);

	spf_pto4(&b, spf->env->c);

	dns_rr_foreach(&rr, pkt, .section = DNS_S_AN, .type = DNS_T_A) {
		if (!dns_d_expand(dn, sizeof dn, rr.dn.p, pkt, &error))
			vm_throw(spf, error);
		if ((error = dns_a_parse((struct dns_a *)&a, &rr, pkt)))
			vm_throw(spf, error);

		if (a.s_addr != b.s_addr)
			continue;

		if ((error = dns_p_push(&spf->ptr, DNS_S_AN, dn, strlen(dn), DNS_T_A, DNS_C_IN, 0, &a)))
			vm_throw(spf, error);
	}

	spf->vm.pc++;
} /* op_verify() */


static void op_revmap(struct spf_resolver *spf, enum vm_opcode code) {
	vm_emit_revmap(spf);
	vm_push(spf, T_INT, spf->vm.pc + 1);
	spf->vm.pc = spf->vm.sub.revmap;
} /* op_revmap() */


static void op_exp(struct spf_resolver *spf, enum vm_opcode code) {
	vm_emit_exp(spf);
	vm_push(spf, T_INT, spf->vm.pc + 1);
	vm_swap(spf);
	spf->vm.pc = spf->vm.sub.exp;
} /* op_exp() */


const struct spf_limits spf_safelimits = { .querymax = 10, };

struct spf_resolver *spf_open(const struct spf_env *env, const struct spf_limits *limits, int *error) {
	struct spf_resolver *spf = 0;

	if (!(spf = malloc(sizeof *spf)))
		goto syerr;

#if 0
//	spf->env    = *env;
//	spf->limits = *limits;

	SPF_LIST_INIT(&spf->rdata);

	dns_p_init(&spf->ptr, sizeof spf->pbuf);
	dns_p_push(&spf->ptr, DNS_S_QD, ".", 1, DNS_T_PTR, DNS_C_IN, 0, 0);

	memset(spf->stack, 0, sizeof spf->stack);

	spf->frame = &spf->stack[0];

	spf_strlcpy(spf->frame->target, spf->env.d, sizeof spf->frame->target);
#endif
	return spf;
syerr:
	*error = errno;

	free(spf);

	return 0;
} /* spf_open() */


void spf_close(struct spf_resolver *spf) {
	struct spf_rr *rr;

	if (!spf)
		return;

#if 0
	while ((rr = SPF_LIST_FIRST(&spf->rdata))) {
		SPF_LIST_REMOVE(&spf->rdata, rr);
		spf_rr_close(rr);
	}
#endif

	free(spf);
} /* spf_close() */


#if 0
enum spf_result spf_check(struct spf_resolver *spf, const char **qname, enum spf_rr_type *qtype, int *error) {
#if 0
	if ((*error = spf_exec(spf)))
		return SPF_SYSERR;

	if (spf->result == SPF_QUERY) {
		*qname = spf->qlast;
		*qtype = spf->qtype;
	} else {
		*qname = 0;
		*qtype = 0;
	}
#endif
	return spf->result;
} /* spf_check() */
#endif


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

#if 0
	if (!(rr = spf_rr_open("25thandClement.com.", SPF_RR_SPF, &error)))
		panic("%s", strerror(error));

	if ((error = spf_rr_parse(rr, 0, policy, strlen(policy))))
		panic("%s", strerror(error));

	spf_rr_close(rr);
#endif
	return 0;
} /* parse() */


static int expand(const char *src, const struct spf_env *env) {
	char dst[512];
	spf_macros_t macros = 0;
	int error;

	if (!(spf_expand(dst, sizeof dst, &macros, src, env, &error)) && error)
		panic("%s: %s", src, strerror(error));	

	fprintf(stdout, "[%s]\n", dst);

	if (SPF_DEBUG(2)) {
		fputs("macros:", stderr);

		for (unsigned M = 'A'; M <= 'Z'; M++) {
			if (spf_used(macros, M))
				{ fputc(' ', stderr); fputc(M, stderr); }
		}

		fputc('\n', stderr);
	}

	return 0;
} /* expand() */


static int macros(const char *src, const struct spf_env *env) {
	spf_macros_t macros = 0;
	int error;

	if (!(spf_expand(0, 0, &macros, src, env, &error)) && error)
		panic("%s: %s", src, strerror(error));	

	for (unsigned M = 'A'; M <= 'Z'; M++) {
		if (spf_used(macros, M)) {
			fputc(M, stdout);
			fputc('\n', stdout);
		}
	}

	return 0;
} /* macros() */


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


int fixdn(int argc, char *argv[]) {
	char dst[(SPF_MAXDN * 2) + 1];
	size_t lim = (SPF_MAXDN + 1), len;
	int flags = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "super")) {
			flags |= SPF_DN_SUPER;
		} else if (!strcmp(argv[i], "trunc")) {
			flags |= SPF_DN_TRUNC;
		} else if (!strncmp(argv[i], "trunc=", 6)) {
			flags |= SPF_DN_TRUNC;
			lim = spf_atoi(&argv[i][6]);
		} else if (!strcmp(argv[i], "anchor")) {
			flags |= SPF_DN_ANCHOR;
		} else if (!strcmp(argv[i], "chomp")) {
			flags |= SPF_DN_CHOMP;
		} else
			panic("%s: invalid flag (\"trunc[=limit]\", \"anchor\", \"chomp\")", argv[i]);
	}

	len = spf_fixdn(dst, argv[0], SPF_MIN(lim, sizeof dst), flags);

	if (SPF_DEBUG(2)) {
		if (len < lim || !len)
			SPF_SAY("%zu[%s]\n", len, dst);
		else if (!lim)
			SPF_SAY("-%zu[%s]\n", (len - lim), dst);
		else
			SPF_SAY("-%zu[%s]\n", (len - lim) + 1, dst);
	}

	puts(dst);

	return 0;
} /* fixdn() */


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
			spf_env_set(&env, opt, optarg);

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
	} else if (!strcmp(argv[0], "macros") && argc > 1) {
		return macros(argv[1], &env);
	} else if (!strcmp(argv[0], "ip6") && argc > 1) {
		return ip6(argc - 1, &argv[1]);
	} else if (!strcmp(argv[0], "ip4") && argc > 1) {
		return ip4(argc - 1, &argv[1]);
	} else if (!strcmp(argv[0], "fixdn") && argc > 1) {
		return fixdn(argc - 1, &argv[1]);
	} else
		goto usage;

	return 0;
} /* main() */


#endif /* SPF_MAIN */
