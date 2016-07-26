#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <err.h>

#include "dns.h"

#define AI_HINTS(af, flags) (&(struct addrinfo){ .ai_family = (af), .ai_flags = (flags) })

#define croak(...) do { warnx(__VA_ARGS__); goto epilog; } while (0)
#define pfree(pp) do { free(*(pp)); *(pp) = NULL; } while (0)
#define ai_close(aip) do { dns_ai_close(*(aip)); *(aip) = NULL; } while (0)

int main(void) {
	struct dns_addrinfo *ai = NULL;
	struct addrinfo *ent = NULL;
	int error, status = 1;

	/*
	 * Bug caused a segfault when calling dns_ai_nextent if we passed a
	 * NULL pointer as the resolver to dns_ai_open. This was previously
	 * allowed as long as AI_NUMERICHOST was specified, but some IPv6
	 * work caused a regression.
	 */
	if (!(ai = dns_ai_open("127.0.0.1", NULL, 0, AI_HINTS(AF_UNSPEC, AI_NUMERICHOST), NULL, &error)))
		goto error;
	if ((error = dns_ai_nextent(&ent, ai))) 
		goto error;
	if (!ent)
		croak("not addrinfo result");
	if (ent->ai_family != AF_INET)
		croak("expected AF of %d, got %d", AF_INET, ent->ai_family);
	if (((struct sockaddr_in *)ent->ai_addr)->sin_addr.s_addr != INADDR_LOOPBACK)
		croak("expected IPv4 loopback address");
	pfree(&ent);
	ai_close(&ai);

	warnx("OK");
	status = 0;

	goto epilog;
error:
	warnx("%s", dns_strerror(error));

	goto epilog;
epilog:
	pfree(&ent);
	ai_close(&ai);

	return status;
}
