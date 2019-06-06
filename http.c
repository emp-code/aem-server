#include <sys/socket.h>

#include "defines.h"
#include "http.h"

void respond_http(const int sock) {
	send(sock, 
		"HTTP/1.1 301 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800\r\n"
		"Location: https://"AEM_DOMAIN"\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"\r\n"
	, 130 + AEM_LEN_DOMAIN, 0);
}
