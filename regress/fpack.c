/* ==========================================================================
 * fpack.c - ASCII binary template parser.
 * --------------------------------------------------------------------------
 * Copyright (c) 2010  William Ahern
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
#include <limits.h>	/* CHAR_BIT */

#include <stdio.h>	/* stdin stdout stderr fwrite(3) fflush(3) fprintf(3) fgetc(3) ungetc(3) fputs(3) tmpfile(3) */
#include <stdlib.h>	/* realloc(3) free(3) */

#include <ctype.h>	/* isprint(3) */

#include <string.h>	/* strerror(3) strlen(3) strcmp(3) */

#include <errno.h>	/* error */

#include <unistd.h>	/* getopt(3) */


/*
 * D E B U G  M A C R O S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static const char *progname;

static enum {
	V_NORM,
	V_DEBUG,
	V_TRACE,
} verbose;

#define DBGit(fmt, ...) \
	do { fprintf(stderr, fmt "%.1s", progname, __func__, __LINE__, __VA_ARGS__); } while (0)

#define SAYit(fmt, ...) \
	do { fprintf(stderr, fmt "%.1s", progname, __VA_ARGS__); } while (0)

#define SAYat(lvl, ...) \
	do { if (verbose >= (lvl)) { \
		if (verbose >= V_TRACE) DBGit("%s:%s:%d: " __VA_ARGS__, "\n"); \
		else SAYit("%s: " __VA_ARGS__, "\n"); \
	} } while (0)

#define SAY(...) SAYat(V_DEBUG, __VA_ARGS__)

#define HAI SAYat(1, "HAI")


/*
 * E R R O R  M A C R O S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define panic(...) \
	do { SAYat(V_NORM, __VA_ARGS__); _Exit(EXIT_FAILURE); } while (0)

#define OOPS(expr, ...) \
	do { if ((expr)) panic(__VA_ARGS__); } while (0)


/*
 * M I S C .  M A C R O S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef MAX
#define MAX(a, b) (((a) > (b))? (a) : (b))
#endif


/*
 * B U F F E R  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct buffer {
	unsigned char *data;
	size_t size, count;
}; /* struct buffer */


static void append(struct buffer *buffer, int ch) {
	if (buffer->count >= buffer->size) {
		size_t size = MAX(1024U, buffer->size * 2U);
		void *tmp   = realloc(buffer->data, size);

		OOPS(!tmp, "realloc: %s", strerror(errno));

		buffer->data = tmp;
		buffer->size = size;
	}

	buffer->data[buffer->count++] = 0xffU & ch;
} /* append() */



/*
 * W O R D  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct word {
	unsigned long value;
	unsigned bits;
}; /* struct word */

static void appendw(struct buffer *buffer, struct word *word) {
	unsigned bytes = (word->bits + 7) / 8;

	SAY("word(%.8X)(%u)", (unsigned int)word->value, word->bits);

	while (bytes--)
		append(buffer, 0xff & (word->value >> (8 * bytes)));

	word->value = 0;
	word->bits  = 0;
} /* appendw() */


/*
 * P A R S E R  R O U T I N E S
 *
 * Format Specification:
 *
 * 	o generally, all non-whitespace characters are literals
 * 	o whitespace is discarded
 * 	o `#' discards all characters till end-of-line
 * 	o `\' begins an escape sequence
 * 		- `\[0-9A-Fa-f]' begins a hexadecimal encoded sequence
 * 		  ending at the first non-hexadecimal character
 * 		- '\n' is a two-character sequence for new line / line feed 
 * 		- '\r' is a two-character sequence for carriage return
 * 		- '\t' is a two-character sequence for vertical tab
 * 		- any other sequence is a two-character sequence producing
 * 		  the second character code literal
 *
 * An unescaped input new line character flushes the output stream.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static size_t fetch(struct buffer *buffer, FILE *fp) {
	struct word w = { 0, 0 };
	_Bool escaped = 0;
	_Bool encoded = 0;
	_Bool comment = 0;
	int ch;

	while (EOF != (ch = getc(fp))) {
		switch (ch) {
		case '#':
			if (escaped)
				goto copy;
			if (encoded)
				goto word;

			comment = 1;

			break;
		case '\\':
			if (escaped)
				goto copy;
			if (encoded)
				goto word;
			if (comment)
				break;

			escaped = 1;

			break;
		case ' ': case '\t': case '\r':
			if (escaped)
				goto copy;
			if (encoded)
				goto word;

			break;
		case '\n':
			if (escaped)
				goto copy;
			if (encoded)
				goto word;

			comment = 0;

			if (buffer->count)
				return buffer->count;

			break;
		case 'n':
			if (escaped)
				{ ch = '\n'; goto copy; }
			if (encoded)
				goto word;
			if (comment)
				break;

			goto copy;
		case 'r':
			if (escaped)
				{ ch = '\r'; goto copy; }
			if (encoded)
				goto word;
			if (comment)
				break;

			goto copy;
		case 't':
			if (escaped)
				{ ch = '\t'; goto copy; }
			if (encoded)
				goto word;
			if (comment)
				break;

			goto copy;
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			if (comment)
				break;
			if (!escaped && !encoded)
				goto copy;

			ch = ch - '0';

			goto nybb;
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
			if (comment)
				break;
			if (!escaped && !encoded)
				goto copy;

			ch = 0x0A + (ch - 'A');

			goto nybb;
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
			if (comment)
				break;
			if (!escaped && !encoded)
				goto copy;

			ch = 0x0a + (ch - 'a');
nybb:
			if (w.bits >= sizeof w.value * CHAR_BIT)
				appendw(buffer, &w);

			w.value <<= 4;
			w.value |= 0x0f & ch;
			w.bits  += 4;

			escaped = 0;
			encoded = 1;

			break;
word:
			ungetc(ch, fp);

			appendw(buffer, &w);

			encoded = 0;

			break;
		default:
			if (encoded)
				goto word;
			if (comment)
				break;
copy:
			if (isprint(ch))
				SAY("char(`%c')", ch);
			else
				SAY("char(0x%.2X)", ch);

			append(buffer, ch);

			escaped = 0;

			break;
		} /* switch() */
	} /* while (getchar()) */

	if (w.bits)
		appendw(buffer, &w);

	return buffer->count;
} /* fetch() */


static void parse(FILE *fp) {
	static struct buffer buffer;

	while (fetch(&buffer, fp)) {
		fwrite(buffer.data, 1, buffer.count, stdout);
		fflush(stdout);
		buffer.count = 0;
	}
} /* parse() */


/*
 * M A I N  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define USAGE \
	"fpack [-f:vh] [string ...]\n" \
	"  -f PATH  parse file instead of stdin or in addition to arguments\n" \
	"  -v       increase verboseness\n" \
	"  -h       print usage\n" \
	"\n" \
	"Report bugs to William Ahern <william@25thandClement.com>\n"


int main(int argc, char *argv[]) {
	const char *path = NULL;
	FILE *file = NULL;
	extern char *optarg;
	extern int optind;
	int opt;

	progname = argv[0];

	while (-1 != (opt = getopt(argc, argv, "f:vh"))) {
		switch (opt) {
		case 'f':
			if (file) {
				SAYat(V_NORM, "using %s instead of %s", optarg, path);
				fclose(file);
			}

			path = optarg;

			if (!strcmp(path, "-"))
				file = fdopen(STDIN_FILENO, "r");
			else
				file = fopen(path, "r");

			OOPS(!file, "%s: %s", path, strerror(errno));

			break;
		case 'v':
			verbose++;

			break;
		case 'h':
			fputs(USAGE, stdout);

			return 0;
		default:
			fputs(USAGE, stderr);

			return EXIT_FAILURE;
		} /* switch() */
	} /* while() */

	argc -= optind;
	argv += optind;

	if (argc) {
		while (*argv) {
			FILE *tmp = tmpfile();
			size_t len, out;

			OOPS(!tmp, "tmpfile: %s", strerror(errno));

			len = strlen(*argv);
			out = fwrite(*argv, 1, len, tmp);

			OOPS(len != out, "fwrite: %s", strerror(errno));

			rewind(tmp);
			parse(tmp);

			fclose(tmp);

			argv++;
		}
	}

	if (file) {
		parse(file);
	} else if (!argc) {
		parse(stdin);
	}

	return 0;
} /* main() */

