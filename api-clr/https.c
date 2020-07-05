#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h> // for islower
#include <syslog.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "../Global.h"
#include "../api-common/post.h"
#include "../Common/tls_common.h"

#include "https.h"

#define AEM_MINLEN_POST 75 // POST /api/account/browse HTTP/1.1\r\nHost: a.bc:302\r\nContent-Length: 8264\r\n\r\n
#define AEM_MAXLEN_REQ 480
#define AEM_CLIENT_TIMEOUT 30

static char domain[AEM_MAXLEN_DOMAIN];
static size_t lenDomain;

#include "../Common/tls_setup.c"

__attribute__((warn_unused_result))
static bool isRequestValid(const char * const req, const size_t lenReq, bool * const keepAlive) {
	if (strcasestr(req, "\r\nConnection: close") != NULL) *keepAlive = false;
	if (lenReq < AEM_MINLEN_POST) return false;
	if (strncmp(req, "POST /api HTTP/1.1\r\n", 20) != 0) return false;

	// Host header
	const char * const host = strstr(req, "\r\nHost: ");
	if (host == NULL) return false;
	if (strncmp(host + 8, domain, lenDomain) != 0) return false;
	if (strncmp(host + 8 + lenDomain, ":302\r\n", 6) != 0) return false;

	if (strstr(req, "\r\nContent-Length: 8328\r\n") == NULL) return false;

	// Forbidden request headers
	if (
		   NULL != strcasestr(req, "\r\nAuthorization:")
		|| NULL != strcasestr(req, "\r\nCookie:")
		|| NULL != strcasestr(req, "\r\nExpect:")
		|| NULL != strcasestr(req, "\r\nHTTP2-Settings:")
		|| NULL != strcasestr(req, "\r\nIf-Match:")
		|| NULL != strcasestr(req, "\r\nIf-Modified-Since:")
		|| NULL != strcasestr(req, "\r\nIf-None-Match:")
		|| NULL != strcasestr(req, "\r\nIf-Range:")
		|| NULL != strcasestr(req, "\r\nIf-Unmodified-Since:")
		|| NULL != strcasestr(req, "\r\nRange:")
		|| NULL != strcasestr(req, "\r\nSec-Fetch-Site: none")
		|| NULL != strcasestr(req, "\r\nSec-Fetch-Site: same-origin")
		// These are only for preflighted requests, which All-Ears doesn't use
		|| NULL != strcasestr(req, "\r\nAccess-Control-Request-Method:")
		|| NULL != strcasestr(req, "\r\nAccess-Control-Request-Headers:")
	) return false;

	const char * const secDest = strcasestr(req, "\r\nSec-Fetch-Dest: ");
	if (secDest != NULL && strncasecmp(secDest + 18, "empty\r\n", 7) != 0) return false;

	const char * const secMode = strcasestr(req, "\r\nSec-Fetch-Mode: ");
	if (secMode != NULL && strncasecmp(secMode + 18, "cors\r\n", 6) != 0) return false;

	return true;
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

	while(1) {
		unsigned char buf[AEM_API_POST_SIZE + crypto_box_MACBYTES];
		do {ret = mbedtls_ssl_read(&ssl, buf, AEM_MAXLEN_REQ + AEM_API_SEALBOX_SIZE);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
		if (ret < 1) break;

		unsigned char * const postBegin = memmem(buf, ret, "\r\n\r\n", 4);
		if (postBegin == NULL) break;
		postBegin[3] = '\0';

		bool keepAlive = true;
		if (!isRequestValid((char*)buf, ret, &keepAlive)) break;

		size_t lenPost = ret - ((postBegin + 4) - buf);
		memmove(buf, postBegin + 4, lenPost);

		if (lenPost < AEM_API_SEALBOX_SIZE) {
			do {ret = mbedtls_ssl_read(&ssl, buf + lenPost, AEM_API_SEALBOX_SIZE - lenPost);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
			if (ret < 1) break;

			lenPost += ret;
			if (lenPost < AEM_API_SEALBOX_SIZE) break;
		}

		if (aem_api_prepare(buf, keepAlive) != 0) break;

		if (lenPost > AEM_API_SEALBOX_SIZE) {
			lenPost -= AEM_API_SEALBOX_SIZE;
			memmove(buf, buf + AEM_API_SEALBOX_SIZE, lenPost);
		} else {
			lenPost = 0;
		}

		while (lenPost < AEM_API_POST_SIZE + crypto_box_MACBYTES) {
			do {ret = mbedtls_ssl_read(&ssl, buf + lenPost, AEM_API_POST_SIZE + crypto_box_MACBYTES - lenPost);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
			if (ret < 1) break;
			lenPost += ret;
		}
		if (ret < 1) break;

		unsigned char *resp;
		const int lenResp = aem_api_process(buf, &resp);
		if (lenResp < 0) break;
		sendData(&ssl, resp, lenResp);

		sodium_memzero(resp, lenResp);
		sodium_memzero(buf, AEM_API_POST_SIZE + crypto_box_MACBYTES);
		if (!keepAlive) break;
	}

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
}
