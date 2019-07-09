#include <string.h>
#include <sys/socket.h>

#include "http.h"

void respond_http(const int sock, const char * const domain) {
	const size_t len = strlen(domain);
	char r[130 + len];

	memcpy(r,
		"HTTP/1.1 301 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"Location: https://"
	, 126);

	memcpy(r + 126, domain, len);
	memcpy(r + 126 + len, "\r\n\r\n", 4);

	send(sock, r, 130 + len, 0);
}
