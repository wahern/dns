
all: rfc4408-tests


CPPFLAGS += -I/usr/local/libyaml/include -I../src -DDNS_DEBUG=0
CFLAGS += -std=gnu99
LDFLAGS += -L/usr/local/libyaml/lib
LIBS += -lyaml

rfc4408-tests: rfc4408-tests.c ../src/cache.c ../src/zone.c ../src/dns.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.c: %.rl
	ragel -C -o $@ $<
