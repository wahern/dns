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

#include <ctype.h>	/* isgraph(3) */

#include <string.h>	/* memcpy(3) strlen(3) */

#include <errno.h>	/* EINVAL ENAMETOOLONG errno */

#include "dns.h"
#include "spf.h"


#if SPF_DEBUG
#include <stdio.h> /* stderr fprintf(3) */

int spf_trace;

#undef SPF_DEBUG
#define SPF_DEBUG spf_trace

#define SPF_TRACE_(fmt, ...) fprintf(stderr, fmt "%.1s", __func__, __LINE__, __VA_ARGS__)
#define SPF_TRACE(...) SPF_TRACE_(">>>> (%s:%d) " __VA_ARGS__, "\n")
#define SPF_MARK 
#else
#define SPF_DEBUG 0

#define SPF_TRACE(...)
#define SPF_MARK
#endif /* SPF_DEBUG */


#define SPF_MIN(a, b)	(((a) < (b))? (a) : (b))


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


/*
 * Normalize domains:
 *
 *   (1) remove leading dots
 *   (2) remove extra dots
 */
size_t spf_trim(char *dst, const char *src, size_t lim) {
	size_t dp = 0, sp = 0;
	int lc;

	/* trim any leading dot(s) */
	while (src[sp] == '.')
		sp++;

	for (lc = 0; src[sp]; lc = src[sp]) {
		if (dp < lim)
			dst[dp] = src[sp];

		sp++; dp++;

		/* trim extra dot(s) */
		while (src[sp] == '.')
			sp++;
	}

	if (lim > 0)
		dst[SPF_MIN(dp, lim - 1)] = '\0';

	return dp;
} /* spf_trim() */


struct spf_sbuf {
	char str[512];
	unsigned end;
	_Bool overflow;
}; /* struct spf_sbuf */

static _Bool spf_sbuf_putc(struct spf_sbuf *sbuf, int ch) {
	if (sbuf->end < sizeof sbuf->str - 1)
		sbuf->str[sbuf->end++] = ch;
	else
		sbuf->overflow = 1;

	return !sbuf->overflow;
} /* spf_sbuf_putc() */

static _Bool spf_sbuf_puts(struct spf_sbuf *sbuf, const char *src) {
	while (*src && spf_sbuf_putc(sbuf, *src))
		src++;

	return !sbuf->overflow;
} /* spf_sbuf_puts() */


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
	case SPF_EXPLANATION:
		return "exp";
	default:
		return "[[[error]]]";
	}
} /* spf_strtype() */




static const struct spf_all spf_all_initializer =
	{ .type = SPF_ALL, .result = SPF_PASS };

static const struct spf_include spf_include_initializer =
	{ .type = SPF_INCLUDE, .result = SPF_PASS, .domain = "%{d}" };

static const struct spf_a spf_a_initializer =
	{ .type = SPF_A, .result = SPF_PASS, .domain = "%{d}", .prefix4 = 32, .prefix6 = 128 };

static const struct spf_mx spf_mx_initializer =
	{ .type = SPF_MX, .result = SPF_PASS, .domain = "%{d}", .prefix4 = 32, .prefix6 = 128 };

static const struct spf_ptr spf_ptr_initializer =
	{ .type = SPF_PTR, .result = SPF_PASS, .domain = "%{d}" };

static const struct spf_ip4 spf_ip4_initializer =
	{ .type = SPF_IP4, .result = SPF_PASS, .prefix = 32 };

static const struct spf_ip6 spf_ip6_initializer =
	{ .type = SPF_IP6, .result = SPF_PASS, .prefix = 128 };

static const struct spf_exists spf_exists_initializer =
	{ .type = SPF_EXISTS, .result = SPF_PASS, .domain = "%{d}" };

static const struct spf_redirect spf_redirect_initializer =
	{ .type = SPF_REDIRECT };

static const struct spf_explanation spf_explanation_initializer =
	{ .type = SPF_EXPLANATION };

static const struct spf_unknown spf_unknown_initializer =
	{ .type = SPF_UNKNOWN };


static const struct {
	const void *initializer;
	size_t size;
	void (*init)();
	void (*reset)();
} spf_term[] = {
	[SPF_ALL]     = { &spf_all_initializer, sizeof spf_all_initializer },
	[SPF_INCLUDE] = { &spf_include_initializer, sizeof spf_include_initializer },
	[SPF_A]       = { &spf_a_initializer, sizeof spf_a_initializer },
	[SPF_MX]      = { &spf_mx_initializer, sizeof spf_mx_initializer },
	[SPF_PTR]     = { &spf_ptr_initializer, sizeof spf_ptr_initializer },
	[SPF_IP4]     = { &spf_ip4_initializer, sizeof spf_ip4_initializer },
	[SPF_IP6]     = { &spf_ip6_initializer, sizeof spf_ip6_initializer },
	[SPF_EXISTS]  = { &spf_exists_initializer, sizeof spf_exists_initializer },

	[SPF_REDIRECT]    = { &spf_redirect_initializer, sizeof spf_redirect_initializer },
	[SPF_EXPLANATION] = { &spf_explanation_initializer, sizeof spf_explanation_initializer },
	[SPF_UNKNOWN]     = { &spf_unknown_initializer, sizeof spf_unknown_initializer },
}; /* spf_term[] */


static void *spf_term_open(int type, int *error) {
	struct spf_term *term;

	if (!(term = malloc(sizeof *term)))
		{ *error = errno; return 0; }

	memset(term, 0, sizeof *term);
	memcpy(term, spf_term[type].initializer, spf_term[type].size);

	if (spf_term[type].init)
		spf_term[type].init(term);

	return term;
} /* spf_term_open() */


static void spf_term_close(void *term) {
	int type = ((struct spf_term *)term)->type;

	if (spf_term[type].reset)
		spf_term[type].reset(term);

	free(term);
} /* spf_term_close() */



%%{
	machine spf_rr_parser;
	alphtype unsigned char;

	action oops {
		if (SPF_DEBUG) {
			const unsigned char *part;

			if (p - (unsigned char *)rdata > 7)
				part = p - 8;
			else
				part = rdata;

			if (isgraph(fc))
				SPF_TRACE("`%c' invalid near `%.*s'", fc, (int)SPF_MIN(12, pe - part), part);
			else
				SPF_TRACE("error near `%.*s'", (int)SPF_MIN(12, pe - part), part);
		}

		error = EINVAL;

		goto error;
	}

	action term_begin {
		result = SPF_PASS;
		memset(&term, 0, sizeof term);
	}

	action term_end {
		if (SPF_ISMECHANISM(term.type))
			SPF_TRACE("term -> %c%s", term.result, spf_strtype(term.type));
		else
			SPF_TRACE("term -> %s", spf_strtype(term.type));
	}

	action all_begin {
		term.all    = spf_all_initializer;
		term.result = result;
	}

	action all_end {
	}

	action include_begin {
		term.include = spf_include_initializer;
		term.result  = result;
	}

	action include_end {
	}

	action a_begin {
		term.a      = spf_a_initializer;
		term.result = result;
	}

	action a_end {
	}

	action mx_begin {
		term.mx    = spf_mx_initializer;
		term.result = result;
	}

	action mx_end {
	}

	action ptr_begin {
		term.ptr    = spf_ptr_initializer;
		term.result = result;
	}

	action ptr_end {
	}

	action ip4_begin {
		term.ip4    = spf_ip4_initializer;
		term.result = result;
	}

	action ip4_end {
	}

	action ip6_begin {
		term.ip6    = spf_ip6_initializer;
		term.result = result;
	}

	action ip6_end {
	}

	action exists_begin {
		term.exists = spf_exists_initializer;
		term.result = result;
	}

	action exists_end {
	}

	action redirect_begin {
		term.redirect = spf_redirect_initializer;
	}

	action redirect_end {
	}

	action exp_begin {
		term.exp = spf_explanation_initializer;
	}

	action exp_end {
	}

	action unknown_begin {
	}

	action unknown_end {
	}

	#
	# SPF RR grammar per RFC 4408 Sec. 15 App. A.
	#
	blank = [ \t];
	name  = alpha (alnum | "-" | "_" | ".")*;

	delimiter     = "." | "-" | "+" | "," | "/" | "_" | "=";
	transformers  = digit* "r"i?;

	macro_letter  = "s"i | "l"i | "o"i | "d"i | "i"i | "p"i | "h"i | "c"i | "r"i | "t"i;
	macro_literal = (0x21 .. 0x24) | (0x26 .. 0x7e);
	macro_expand  = ("%{" macro_letter transformers delimiter* "}") | "%%" | "%_" | "%-";
	macro_string  = (macro_expand | macro_literal)*;

	toplabel    = (digit* alpha alnum*) | (alnum+ "-" (alnum | "-")* alnum);
	domain_end  = ("." toplabel "."?) | macro_expand;
	domain_spec = macro_string domain_end;

	qnum        = ("0" | ("3" .. "9"))
	            | ("1" digit{0,2})
	            | ("2" ( ("0" .. "4" digit?)?
	                   | ("5" ("0" .. "4")?)?
	                   | ("6" .. "9")?
	                   )
	              );
	ip4_network = qnum "." qnum "." qnum "." qnum;
	ip6_network = (xdigit | ":" | ".")+;

	ip4_cidr_length  = "/" digit+;
	ip6_cidr_length  = "/" digit+;
	dual_cidr_length = ip4_cidr_length? ("/" ip6_cidr_length)?;

	unknown     = name "=" macro_string;
	explanation = "exp"i %exp_begin "=" domain_spec;
	redirect    = "redirect"i %redirect_begin "=" domain_spec;
	modifier    = redirect | explanation | unknown;

	exists  = "exists"i %exists_begin ":" domain_spec;
	IP6     = "ip6"i %ip6_begin ":" ip6_network ip6_cidr_length?;
	IP4     = "ip4"i %ip4_begin ":" ip4_network ip4_cidr_length?;
	PTR     = "ptr"i %ptr_begin (":" domain_spec)?;
	MX      = "mx"i %mx_begin (":" domain_spec)? dual_cidr_length?;
	A       = "a"i %a_begin (":" domain_spec)? dual_cidr_length?;
	inklude = "include"i %include_begin ":" domain_spec;
	all     = "all"i %all_begin;

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


struct spf_rr *spf_rr_open(const char *qname, enum spf_rtype rtype, int *error) {
	struct spf_rr *rr;

	if (!(rr = malloc(sizeof *rr)))
		goto syerr;

	memset(rr, 0, sizeof *rr);

	SPF_INIT(&rr->terms);

	if (sizeof rr->qname <= spf_trim(rr->qname, qname, sizeof rr->qname))
		{ *error = ENAMETOOLONG; goto error; }

	rr->rtype = rtype;

	return rr;
syerr:
	*error = errno;
error:
	free(rr);

	return 0;
} /* spf_rr_open() */


void spf_rr_close(struct spf_rr *rr) {
	if (!rr)
		return;

	
} /* spf_rr_close() */



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

	if (!(rr = spf_rr_open("25thandClement.com.", SPF_T_TXT, &error)))
		panic("%s", strerror(error));

	if ((error = spf_rr_parse(rr, policy, strlen(policy))))
		panic("%s", strerror(error));

	spf_rr_close(rr);

	return 0;
} /* parse() */


#define USAGE \
	"spf [-vh] parse <POLICY>\n" \
	"  -v  Be verbose\n" \
	"  -h  Print usage\n" \
	"\n" \
	"Reports bugs to william@25thandClement.com\n"

int main(int argc, char **argv) {
	extern int optind;
	int opt;

	while (-1 != (opt = getopt(argc, argv, "vh"))) {
		switch (opt) {
		case 'v':
			spf_trace++;

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
	} else
		goto usage;

	return 0;
} /* main() */


#endif /* SPF_MAIN */
