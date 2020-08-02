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

#include "https.h"

#define AEM_MINLEN_GET 30 // GET / HTTP/1.1\r\nHost: a.bc\r\n\r\n
#define AEM_MAXLEN_REQ 800
#define AEM_CLIENT_TIMEOUT 30

static char req[AEM_MAXLEN_REQ + 1];

static unsigned char *html;
static size_t lenHtml = 0;

static char domain[AEM_MAXLEN_DOMAIN];
static size_t lenDomain;

#include "../Common/tls_setup.c"

int setHtml(const unsigned char * const data, const size_t len) {
	html = sodium_malloc(len);
	if (html == NULL) return -1;

	memcpy(html, data, len);
	sodium_mprotect_readonly(html);
	lenHtml = len;
	return 0;
}

void freeHtml(void) {
	if (lenHtml == 0) return;
	sodium_free(html);
	lenHtml = 0;
}

static void respond_mtasts(void) {
	char data[377 + lenDomain];
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Cache-Control: public, max-age=9999999, immutable\r\n"
		"Connection: close\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Tk: N\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-Robots-Tag: noindex\r\n"
		"\r\n"
		"version: STSv1\n"
		"mode: enforce\n"
		"mx: %.*s\n"
		"max_age: 31557600"
	, 51 + lenDomain, (int)lenDomain, domain);

	sendData(&ssl, data, 376 + lenDomain);
}

static void handleRequest(const size_t lenReq) {
	if (memcmp(req, "GET /", 5) != 0) return;

	const char * const reqEnd = strstr(req, "\r\n\r\n");
	if (reqEnd == NULL) return;
	if (reqEnd + 4 != req + lenReq) return;

	// Host header
	const char * const host = strstr(req, "\r\nHost: ");
	if (host == NULL) return;
	if (strncmp(host + 8, "mta-sts.", 8) == 0) return respond_mtasts();
	if (strncmp(host + 8, domain, lenDomain) != 0) return;
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

	sendData(&ssl, html, lenHtml);
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
