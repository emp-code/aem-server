#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/tls_common.h"
#include "../Data/html.h"

#include "https.h"

#define AEM_MINLEN_GET 30 // GET / HTTP/1.1\r\nHost: a.bc\r\n\r\n
#define AEM_MAXLEN_REQ 800

static char req[AEM_MAXLEN_REQ + 1];

#include "../Common/tls_setup.c"

static void handleRequest(const size_t lenReq) {
	if (memcmp(req, "GET /", 5) != 0) return;

	const char * const reqEnd = strstr(req, "\r\n\r\n");
	if (reqEnd == NULL) return;
	if (reqEnd + 4 != req + lenReq) return;

	// Host header
	const char * const host = strstr(req, "\r\nHost: ");
	if (host == NULL) return;
	if (strncmp(host + 8, "mta-sts.", 8) == 0) {sendData(&ssl, AEM_MTASTS_DATA, AEM_MTASTS_SIZE); return;}
	if (strncmp(host + 8, AEM_DOMAIN, AEM_DOMAIN_LEN) != 0) return;
	if (strncmp(req + 5, " HTTP/1.1\r\n", 11) != 0) return;

	// Forbidden request headers
	if (
		   NULL != strcasestr(req, "\r\nAccess-Control-")
		|| NULL != strcasestr(req, "\r\nAuthorization:")
		|| NULL != strcasestr(req, "\r\nContent-Length:")
		|| NULL != strcasestr(req, "\r\nCookie:")
		|| NULL != strcasestr(req, "\r\nExpect:")
		|| NULL != strcasestr(req, "\r\nOrigin:")
		|| NULL != strcasestr(req, "\r\nRange:")
		|| NULL != strcasestr(req, "\r\nX-Requested-With:")
	) return;

	const char * const fetchMode = strcasestr(req, "\r\nSec-Fetch-Mode: ");
	if (fetchMode != NULL && strncasecmp(fetchMode + 18, "navigate\r\n", 10) != 0) return;

	const char * const fetchDest = strcasestr(req, "\r\nSec-Fetch-Dest: ");
	if (fetchDest != NULL && strncasecmp(fetchDest + 18, "document\r\n", 10) != 0) return;

	sendData(&ssl, AEM_HTML_CLR_DATA, AEM_HTML_CLR_SIZE);
}

void respondClient(int sock) {
	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	int ret;
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			syslog(LOG_DEBUG, "mbedtls_ssl_handshake failed: %d", ret);
			mbedtls_ssl_close_notify(&ssl);
			mbedtls_ssl_session_reset(&ssl);
			return;
		}
	}

	do {ret = mbedtls_ssl_read(&ssl, (unsigned char*)req, AEM_MAXLEN_REQ);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

	if (ret >= AEM_MINLEN_GET) {
		req[ret] = '\0';
		handleRequest(ret);
	}

	sodium_memzero(req, AEM_MAXLEN_REQ);
	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
}
