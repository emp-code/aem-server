#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>

#include "../Global.h"
#include "../api-common/post.h"

#include "http.h"

#define AEM_MINLEN_POST 133 // POST /api/account/browse HTTP/1.1\r\nHost: gt2wj6tc4b9wr21q3sjvro2jfem1j7cf00626cz4t1bksflt8kjqgjf8.onion:302\r\nContent-Length: 8264\r\n\r\n
#define AEM_MAXLEN_REQ 540
#define AEM_CLIENT_TIMEOUT 30

//static char onionId[56];

__attribute__((warn_unused_result))
static bool isRequestValid(const char * const req, const size_t lenReq, bool * const keepAlive) {
	if (strcasestr(req, "\r\nConnection: close") != NULL) *keepAlive = false;
	if (lenReq < AEM_MINLEN_POST) return false;
	if (strncmp(req, "POST /api HTTP/1.1\r\n", 20) != 0) return false;

	// Host header
//	const char * const host = strstr(req, "\r\nHost: ");
//	if (host == NULL) return false;
//	if (strncmp(host + 8, onionId, 56) != 0) return false;
//	if (strncmp(host + 64, ".onion:302\r\n", 12) != 0) return false;

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

void respondClient(const int sock) {
	while(1) {
		unsigned char buf[AEM_API_POST_SIZE + crypto_box_MACBYTES];
		int ret = recv(sock, buf, AEM_MAXLEN_REQ + AEM_API_SEALBOX_SIZE, 0);
		if (ret < 1) return;

		unsigned char * const postBegin = memmem(buf, ret, "\r\n\r\n", 4);
		if (postBegin == NULL) return;
		postBegin[3] = '\0';

		bool keepAlive = true;
		if (!isRequestValid((char*)buf, ret, &keepAlive)) return;

		size_t lenPost = ret - ((postBegin + 4) - buf);
		memmove(buf, postBegin + 4, lenPost);

		if (lenPost < AEM_API_SEALBOX_SIZE) {
			ret = recv(sock, buf + lenPost, AEM_API_SEALBOX_SIZE - lenPost, 0);
			if (ret < 1) return;

			lenPost += ret;
			if (lenPost < AEM_API_SEALBOX_SIZE) return;
		}

		if (aem_api_prepare(buf, keepAlive) != 0) return;

		if (lenPost > AEM_API_SEALBOX_SIZE) {
			lenPost -= AEM_API_SEALBOX_SIZE;
			memmove(buf, buf + AEM_API_SEALBOX_SIZE, lenPost);
		} else {
			lenPost = 0;
		}

		while (lenPost < AEM_API_POST_SIZE + crypto_box_MACBYTES) {
			ret = recv(sock, buf + lenPost, AEM_API_POST_SIZE + crypto_box_MACBYTES - lenPost, 0);
			if (ret < 1) return;
			lenPost += ret;
		}

		unsigned char *resp;
		const int lenResp = aem_api_process(buf, &resp);
		if (lenResp < 0) break;
		send(sock, resp, lenResp, 0);

		sodium_memzero(resp, lenResp);
		sodium_memzero(buf, AEM_API_POST_SIZE + crypto_box_MACBYTES);
		if (!keepAlive) return;
	}
}
