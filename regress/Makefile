
all: rfc4408-tests


CPPFLAGS += -I/usr/local/libyaml/include -I../src -DDNS_DEBUG=0 -DSPF_DEBUG=1 -DVM_MAXCODE=3182
CFLAGS += -std=gnu99 -g
LDFLAGS += -L/usr/local/libyaml/lib
LIBS += -lyaml

rfc4408-tests: rfc4408-tests.c ../src/cache.c ../src/zone.c ../src/spf.c ../src/dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.c: %.rl
	ragel -C -o $@ $<

clean:
	rm -f rfc4408-tests fpack
	rm -fr *.dSYM

