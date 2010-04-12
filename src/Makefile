CPPFLAGS	+= -DDNS_DEBUG -DDNS_MAIN
CFLAGS		+= -std=c99 -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-parameter -O2 -g -fstack-protector

EXE_CC		= mingw32-gcc
EXE_CPPFLAGS	+= $(CPPFLAGS)
EXE_CFLAGS	+= -std=gnu99 -Wall -Werror -Wno-unused-function -Wno-unused-label -O2 -g -fstack-protector
EXE_LIBS	+= -lws2_32 -lgdi32

all: dns

dns: dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

dns.exe: dns.c
	$(EXE_CC) $(EXE_CFLAGS) $(EXE_CPPFLAGS) -o $@ $^ $(EXE_LIBS)

dns.S: dns.c
	$(CC) $(CFLAGS) -S $(CPPFLAGS) -o $@ $^


SPF_CPPFLAGS += 
SPF_CFLAGS   += -std=gnu99 -Wall -Werror -Wno-unused-function -Wno-unused-variable -O2 -g -fstack-protector

%.c: %.rl
	ragel -C -o $@ $<

spf: spf.c dns.c
	$(CC) $(SPF_CFLAGS) $(SPF_CPPFLAGS) -DSPF_MAIN -DSPF_DEBUG -o $@ $^

.PHONY: check spf.t

spf.t: spf
	@PATH=".:$${PATH}"; $@ -p $^

check: spf.t


ZONE_CPPFLAGS += -I../compat/bsd -I../compat
ZONE_CFLAGS   += $(SPF_CFLAGS)

zone: zone.c dns.c
	$(CC) $(ZONE_CFLAGS) $(ZONE_CPPFLAGS) -DZONE_MAIN -o $@ $^


CACHE_CPPFLAGS += -I../compat/bsd -I../compat
CACHE_CFLAGS   += $(SPF_CFLAGS)

cache: cache.c zone.c dns.c
	$(CC) $(CACHE_CFLAGS) $(CACHE_CPPFLAGS) -DCACHE_MAIN -o $@ $^


.PHONY: clean

clean:
	rm -f dns dns.exe spf spf.c
	rm -fr dns.dSYM spf.dSYM
