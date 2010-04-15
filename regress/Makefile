
all: rfc4408-tests


CPPFLAGS += -I/usr/local/libyaml/include -I../src -DDNS_DEBUG=0 -DSPF_DEBUG=1
CFLAGS += -std=gnu99
LDFLAGS += -L/usr/local/libyaml/lib
LIBS += -lyaml

rfc4408-tests: rfc4408-tests.c ../src/cache.c ../src/zone.c ../src/spf.c ../src/dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.c: %.rl
	ragel -C -o $@ $<

clean:
	rm -f rfc4408-tests

