CPPFLAGS	+= -DDNS_DEBUG -DDNS_MAIN -DDNS_TRACE=dns_trace
CFLAGS		+= -std=c99 -Wall -Werror -Wno-unused-function -O2 -g -fstack-protector


all: dns

dns.S: dns.c
	$(CC) $(CFLAGS) -S $(CPPFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -f dns
	rm -fr dns.dSYM
