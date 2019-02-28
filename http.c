#include <sys/socket.h>

#include "defines.h"
#include "http.h"

void respond_http(const int sock) {
	send(sock, 
		"HTTP/1.1 301 aem\r\n"
		"TSV: N\r\n"
		"Location: https://"AEM_DOMAIN"\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"Strict-Transport-Security: max-age=99999999\r\n" // 3+ years
		"\r\n";
	, 131 + AEM_LEN_DOMAIN, 0);
}
