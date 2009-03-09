CPPFLAGS	+= -DDNS_DEBUG -DDNS_MAIN -DDNS_TRACE=dns_trace
CFLAGS		+= -std=c99 -Wall -Werror -Wno-unused-function -O2 -g -fstack-protector

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

.PHONY: clean

clean:
	rm -f dns dns.exe
	rm -fr dns.dSYM
