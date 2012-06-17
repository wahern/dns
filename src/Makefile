#
# This Makefile is provided as an example, and principally used when
# compiling the command-line regression utilities. Effort is made to make
# dns.c compile as cleanly as possible, but this is becoming an increasingly
# difficult task, particularly with clang, which has a habit of emitting
# warnings on perfectly valid C code. Clang's guideline appears to be that
# if the warning can catch any bad code, even if valid code, then it's a
# candidate as a default warning. Regardless of the soundness of that
# guideline, one necessary consequence is that the value and urgency of
# other warnings is necessarily diminished. Clang has come perilously close
# to mandating style rather than conformance.
#
#
# I'm often conflicted about "unused" warnings, particularly for parameters,
# labels, and functions. I tend to code by mentally constructing an abstract
# API, and then filling in the blanks with code and accessory routines. It's
# often the case that a particular routine or parameter goes unused, but
# which I prefer to keep around as a reminder of future enhancements or
# refactoring opportunities. Preventing this information from disappearing
# into the void by keeping it conspicuous is often more valuable to me than
# quieting shrill compiler warnings. Thus the use of GCC's "unused"
# attribution in several areas in the codebase.
#
#
# Presently there are two warning types in GCC and clang which cause false
# positives with dns.c, and which cannot be easily remedied because the fix
# would be foolish.
#
# 1) With named initializers one can redefine the value of a member multiple
#    times within the same initializer. This is well-defined behavior, and
#    the last definition controls according to the standard. This behavior
#    is relied upon to allow user code to override default values set from
#    macroized initializers. Combined with compound literals, this behavior
#    allows for some concise and convenient constructs. It would be a
#    headache, and the result needlessly obstrusive, to refactor code using
#    these macros.
#
#    a) GCC emits initializer warnings with -Wextra. To disable, use
#
#    	-Wno-override-init
#
#    b) clang emits initializer warnings by default. To disable, use
#
#       -Wno-initializer-overrides
#
#  2) The socket code uses negative indexing to load and store the TCP
#     header. The packet structure uses an anonymous member to provide
#     padding, making this a safe operation. Refactoring TCP header
#     manipulation would add almost infinite complexity over the existing,
#     exceedingly clear and concise code.
#
#     a) clang emits array-bounds warnings by default. To disable, use
#
#        -Wno-array-bounds
#
#
cc-option = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi;)

CPPFLAGS	+= -DDNS_DEBUG -DDNS_MAIN
CFLAGS		+= -std=gnu99 -Wall -O2 -g -fstack-protector $(call cc-option, -Wno-override-init) $(call cc-option, -Wno-initializer-overrides) $(call cc-option, -Wno-array-bounds)

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
SPF_CFLAGS   += -std=gnu99 -Wall -Wno-unused-function -Wno-unused-variable -O2 -g -fstack-protector

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
