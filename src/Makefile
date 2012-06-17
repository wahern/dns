#
# This Makefile is provided as an example, and principally used when
# compiling the command-line regression utilities.
#
# RE COMPILER WARNINGS: Effort is made to make dns.c compile as cleanly as
# possible, although often times I will use compiler attributes or pragmas
# to quiet warnings where refactoring would discard perfectly clear,
# concise, and correct code.
#
# RE VISUAL STUDIO: dns.c will not compile with Visual Studio. Microsoft has
# frozen C support at C95, whereas dns.c uses some newer C99 and C11
# constructs not available in C95 or as MSVC extensions. dns.c could be made
# to compile with MSVC with moderate effort, however, some aspects of the
# dns.c API require these newer features, so MSVC support would always play
# second fiddle.
#
CPPFLAGS	+= -DDNS_DEBUG -DDNS_MAIN
CFLAGS		+= -std=gnu99 -Wall -Wextra -O2 -g -fstack-protector

EXE_CC		= $(shell find $$(echo $${PATH} | tr ':' ' ') -maxdepth 1 -name \*mingw32-gcc -o -name gcc-\* | while read GCC; do echo $$($$GCC -v 2>&1 | tail -n1 | cut -d' ' -f3) $$GCC; done | sort -nr | head -n1 | cut -d' ' -f2)
EXE_CPPFLAGS	+= $(CPPFLAGS)
EXE_CFLAGS	+= -std=gnu99 -Wall -O2 -g
EXE_LIBS	+= -lws2_32 -lgdi32

all: dns

dns: dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

dns.exe: dns.c
	$(EXE_CC) $(EXE_CFLAGS) $(EXE_CPPFLAGS) -o $@ $^ $(EXE_LIBS)

dns.S: dns.c
	$(CC) $(CFLAGS) -S $(CPPFLAGS) -o $@ $^


SPF_CPPFLAGS += 
SPF_CFLAGS   += -std=gnu99 -Wall -O2 -g -fstack-protector

%.c: %.rl
	ragel -C -o $@ $<

spf: spf.c cache.c zone.c dns.c
	$(CC) $(SPF_CFLAGS) $(SPF_CPPFLAGS) -DSPF_MAIN -DSPF_DEBUG -DSPF_CACHE=1 -o $@ $^

.PHONY: check spf.t

spf.t: spf
	@PATH=".:$${PATH}"; $@ -p $^

check: spf.t


ZONE_CPPFLAGS += 
ZONE_CFLAGS   += $(SPF_CFLAGS)

zone: zone.c dns.c
	$(CC) $(ZONE_CFLAGS) $(ZONE_CPPFLAGS) -DZONE_MAIN -o $@ $^


CACHE_CPPFLAGS += 
CACHE_CFLAGS   += $(SPF_CFLAGS)

cache: cache.c zone.c dns.c
	$(CC) $(CACHE_CFLAGS) $(CACHE_CPPFLAGS) -DCACHE_MAIN -o $@ $^


.PHONY: clean

clean:
	rm -f dns dns.S dns.exe spf spf.c cache cache.o zone zone.o zone.c
	rm -fr *.dSYM
