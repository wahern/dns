
all: rfc4408-tests 12-segfault-in-dns_res_frame_init


CPPFLAGS += -I/usr/local/libyaml/include -I../src -DDNS_DEBUG=0 -DSPF_DEBUG=1 -DVM_MAXCODE=3182
CFLAGS += -std=gnu99 -g
LDFLAGS += -L/usr/local/libyaml/lib
LIBS += -lyaml

rfc4408-tests: rfc4408-tests.c ../src/cache.c ../src/zone.c ../src/spf.c ../src/dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.c: %.rl
	ragel -C -o $@ $<

12-segfault-in-dns_res_frame_init: 12-segfault-in-dns_res_frame_init.c ../src/dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f rfc4408-tests fpack 12-segfault-in-dns_res_frame_init
	rm -fr *.dSYM

