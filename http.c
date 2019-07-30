#include <string.h>
#include <unistd.h>

#include "http.h"

void respond_http(const int sock, const char * const domain, const size_t lenDomain) {
	char r[115 + lenDomain];

	memcpy(r,
		"HTTP/1.1 301 aem\r\n"
		"Tk: N\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"Referrer-Policy: no-referrer\r\n"
		"Location: https://"
	, 111);

	memcpy(r + 111, domain, lenDomain);
	memcpy(r + 111 + lenDomain, "\r\n\r\n", 4);

	write(sock, r, 115 + lenDomain);
	close(sock);
}
