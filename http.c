#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "http.h"

void respond_http(const int sock, const char *domain) {
	const size_t len = strlen(domain);
	char r[131 + len];

	sprintf(r,
		"HTTP/1.1 301 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800\r\n"
		"Location: https://%s\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n"
	, domain);

	send(sock, r, 130 + len, 0);
}
