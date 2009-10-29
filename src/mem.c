#include <limits.h>	/* CHAR_BIT */

#include <string.h>	/* strlen(3) */

#include <errno.h>	/* ENOMEM errno */

#include <sys/param.h>	/* howmany setbit clrbit isset */

#define PAGESIZE  4096
#define SLOTSIZE  16
#define SLOTCOUNT (PAGESIZE/SLOTSIZE)

#define FIRSTFIT 0
#define BESTFIT  1
#define HOWFIT   BESTFIT


struct page {
	unsigned char index[howmany(SLOTCOUNT, CHAR_BIT)];
	unsigned char ptr[howmany(SLOTCOUNT, CHAR_BIT)];

	unsigned char data[PAGESIZE];
}; /* struct page */

struct slot {
	unsigned base, count;
}; /* struct slot */


static struct slot toslot(struct page *page, void *p) {
	struct slot slot;
	unsigned end;

	slot.base = ((unsigned char *)p - &page->data[0]) / SLOTSIZE;

	for (end = slot.base; end < SLOTCOUNT && isset(page->index, end); end++)
		;;

	slot.count = end - slot.base;

	return slot;
} /* toslot() */


static void scan(struct page *page, struct slot *slot, unsigned *next) {
	unsigned base, end;

	for (base = *next; base < SLOTCOUNT && isset(page->index, base); base++)
		;;

	for (end = base; end < SLOTCOUNT && isclr(page->index, end); end++)
		;;

	*next = end;

	slot->base  = base;
	slot->count = end - base;
} /* scan() */


void *get(struct page *page, size_t size) {
	unsigned count = howmany(size, SLOTSIZE);
	unsigned next  = 0;
	struct slot slot;
	void *p;

	do {
		scan(page, &slot, &next);
	} while (slot.count && slot.count < count);

	if (!slot.count)
		{ errno = ENOMEM; return 0; }

#if HOWFIT == BESTFIT
	if (slot.count != count) {
		struct slot tmp;

		do {
			do {
				scan(page, &tmp, &next);
			} while (tmp.count && tmp.count < count);

			if (tmp.count >= count && tmp.count < slot.count)
				slot = tmp;
		} while (tmp.count);
	}
#endif

	p = &page->data[slot.base * SLOTSIZE];

	setbit(page->ptr, slot.base);

	while (count--) {
		setbit(page->index, slot.base);
		slot.base++;
	}

	return p;
} /* get() */


void put(struct page *page, void *p) {
	struct slot slot = toslot(page, p);

	clrbit(page->ptr, slot.base);

	while (slot.count--) {
		clrbit(page->index, slot.base);
		slot.base++;
	}
} /* put() */


void *mdup(struct page *page, const void *src, size_t len) {
        char *dst = get(page, len);
        return (dst)? memcpy(dst, src, len): 0;
} /* mdup() */


char *sdup(struct page *page, const char *src) {
        return mdup(page, src, strlen(src) + 1);
} /* sdup() */


#if 1

#include <stdlib.h>	/* EXIT_FAILURE */
#include <stdio.h>	/* fputc(3) fputs(3) fprintf(3) */

#include <string.h>	/* perror(3) */

#include <ctype.h>	/* isprint(3) */

#include <locale.h>	/* LC_ALL setlocale(3) */

#include <sys/param.h>	/* setbit clrbit */

#include <unistd.h>	/* getopt(3) */


static void frepc(int ch, int count, FILE *fp)
        { while (count--) fputc(ch, fp); }

void printslot(struct page *page, struct slot *slot, FILE *fp) {
	static const char hex[] = "01234567890abcdef";
	unsigned p, pe, i;

	p  = slot->base * SLOTSIZE;
	pe = p + (slot->count * SLOTSIZE);

	do {
                fputs(" ", fp);

                for (i = 0; p + i < pe && i < 16; i++) {
                        fputc(hex[0x0f & (page->data[p + i] >> 4)], fp);
                        fputc(hex[0x0f & (page->data[p + i] >> 0)], fp);
                        fputc(' ', fp);
                }

                frepc(' ', 18 - i, fp);

                for (i = 0; p + i < pe && i < 16; i++)
                        fputc((isprint(page->data[p + i]))? page->data[p + i] : '.', fp);

                fputc('\n', fp);
                p += 16;
        } while (p < pe);
} /* printslot() */


void printpage(struct page *page, FILE *fp) {
	struct slot slot = { 0 };
	unsigned end;

	while (slot.base < SLOTCOUNT) {
		while (isclr(page->ptr, slot.base)) {
			if (++slot.base >= SLOTCOUNT)
				return;
		}

		for (end = slot.base + 1; end < SLOTCOUNT && isset(page->index, end) && isclr(page->ptr, end); end++)
			;;

		slot.count = end - slot.base;

		fprintf(fp, "(%u:%u)\n", slot.base, slot.count);
		printslot(page, &slot, fp);

		slot.base += slot.count;
	}
} /* printpage() */


int main(int argc, char *argv[]) {
	static const unsigned primes[] =
		{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
		  59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
		  127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
		  191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251 };
	struct page page;
	char word[256], *str;
	int opt, frag = 0;
	unsigned i;

	setlocale(LC_ALL, "C");

	while (-1 != (opt = getopt(argc, argv, "fh"))) {
		switch (opt) {
		case 'f':
			frag = 1;
			break;
		default:
			fprintf(stderr,
				"%s [-fh]\n"
				"  -f  Fragment memory\n"
				"  -h  Print usage\n\n"
				"Report bugs to <william@25thandClement.com>\n", argv[0]);
			return (opt == 'h')? 0 : EXIT_FAILURE;
		} /* switch() */
	}

	memset(&page, 0, sizeof page);

	for (i = 0; frag && i < sizeof primes / sizeof primes[0] && i < SLOTCOUNT; i++)
        	setbit(page.index, primes[i]);

	while (EOF != scanf("%256s", word)) {
		if (!(str = sdup(&page, word)))
			perror("sdup");
	}

	for (i = 0; frag && i < sizeof primes / sizeof primes[0] && i < SLOTCOUNT; i++)
		clrbit(page.index, primes[i]);

	printpage(&page, stdout);

	return 0;
} /* main() */

#endif /* MAIN */
