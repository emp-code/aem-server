#include <stdbool.h>
#include <string.h>
#include <syslog.h>

#ifdef AEM_API_CLR
	#include "../Common/tls_common.h"
#else
	#include <sys/socket.h>
	#include <sys/types.h>
#endif

#define AEM_MAXLEN_REQ 500

#include "../Global.h"
#include "isRequestValid.h"
#include "post.h"

#ifdef AEM_API_CLR
	#include "../Common/tls_setup.c"
#endif

#include "http.h"

void respondClient(int sock) {
#ifdef AEM_API_CLR
	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	int ret;
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			syslog(LOG_DEBUG, "mbedtls_ssl_handshake failed: %x", -ret);
			mbedtls_ssl_close_notify(&ssl);
			mbedtls_ssl_session_reset(&ssl);
			return;
		}
	}
#endif

	unsigned char buf[AEM_MAXLEN_REQ];
	unsigned char * const box = sodium_malloc(AEM_API_BOX_SIZE_MAX + crypto_box_MACBYTES);
	if (box == NULL) {
		syslog(LOG_ERR, "Failed sodium_malloc()");
#ifdef AEM_API_CLR
		mbedtls_ssl_close_notify(&ssl);
		mbedtls_ssl_session_reset(&ssl);
#endif
		return;
	}

	while(1) {
#ifdef AEM_API_CLR
		do {ret = mbedtls_ssl_read(&ssl, buf, AEM_MAXLEN_REQ);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
#else
		int ret = recv(sock, buf, AEM_MAXLEN_REQ, 0);
#endif
		if (ret < 1) break;

		unsigned char * const postBegin = memmem(buf, ret, "\r\n\r\n", 4);
		if (postBegin == NULL) break;
		postBegin[3] = '\0';

		long clen = 0;
		bool keepAlive = true;
		if (!isRequestValid((char*)buf, ret, &keepAlive, &clen)) break;

		size_t lenPost = ret - ((postBegin + 4) - buf);
		if (lenPost > 0) memmove(buf, postBegin + 4, lenPost);

		if (lenPost < AEM_API_SEALBOX_SIZE) {
#ifdef AEM_API_CLR
			do {ret = mbedtls_ssl_read(&ssl, buf + lenPost, AEM_API_SEALBOX_SIZE - lenPost);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
#else
			ret = recv(sock, buf + lenPost, AEM_API_SEALBOX_SIZE - lenPost, 0);
#endif

			if (ret < 1) break;
			lenPost += ret;
		}
		if (lenPost < AEM_API_SEALBOX_SIZE) break;

		ret = aem_api_prepare(buf, keepAlive);
		if (ret != AEM_INTCOM_RESPONSE_OK) {
			char txt[] =
				"HTTP/1.1 500 aem\r\n"
				"Tk: N\r\n"
#ifdef AEM_API_CLR
				"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
				"Expect-CT: enforce, max-age=99999999\r\n"
#endif
				"Content-Length: 0\r\n"
				"Access-Control-Allow-Origin: *\r\n"
				"Connection: close\r\n"
				"\r\n"
			;

			if (ret == AEM_INTCOM_RESPONSE_CRYPTO) txt[9] = '4'; // 400
			else if (ret == AEM_INTCOM_RESPONSE_NOTEXIST) {txt[9] = '4'; txt[11] = '3';} // 403
			else if (ret == AEM_INTCOM_RESPONSE_LIMIT) {txt[9] = '4'; txt[10] = '9'; txt[11] = '9';} // 499

#ifdef AEM_API_CLR
			sendData(&ssl, txt, 208);
#else
			send(sock, txt, 97, 0);
#endif
			break;
		}

		// Request is valid
		const size_t lenBox = clen - AEM_API_SEALBOX_SIZE;

		if (lenPost > AEM_API_SEALBOX_SIZE) {
			memcpy(box, buf + AEM_API_SEALBOX_SIZE, lenPost - AEM_API_SEALBOX_SIZE);
			lenPost -= AEM_API_SEALBOX_SIZE;
		} else lenPost = 0;

		while (lenPost < lenBox) {
#ifdef AEM_API_CLR
			do {ret = mbedtls_ssl_read(&ssl, box + lenPost, lenBox - lenPost);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
#else
			ret = recv(sock, box + lenPost, lenBox - lenPost, 0);
#endif
			if (ret < 1) break;
			lenPost += ret;
		}
		if (lenPost != lenBox) break;

		unsigned char *resp;
		const int lenResp = aem_api_process(box, lenBox, &resp);

		sodium_memzero(buf, AEM_MAXLEN_REQ);
		sodium_memzero(box, lenBox);

		if (lenResp < 0) break;
#ifdef AEM_API_CLR
		sendData(&ssl, resp, lenResp);
#else
		send(sock, resp, lenResp, 0);
#endif
		sodium_memzero(resp, lenResp);

		if (!keepAlive) break;
	}

	sodium_free(box);
#ifdef AEM_API_CLR
	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
#endif
}
