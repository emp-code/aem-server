#define _GNU_SOURCE // for memmem, strcasestr

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
#include "../Common/https_suites.h"

#include "https.h"
#include "post.h"

#define AEM_MINLEN_POST 75 // POST /api/account/browse HTTP/1.1\r\nHost: a.bc:302\r\nContent-Length: 8264\r\n\r\n
#define AEM_MAXLEN_REQ 480
#define AEM_HTTPS_TIMEOUT 30

#define AEM_SKIP_URL_POST 10 // 'POST /api/'
#define AEM_LEN_URL_POST 14 // 'account/browse'

static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static const int https_ciphersuites[] = {AEM_TLS_CIPHERSUITES_HIGH};
static const mbedtls_ecp_group_id https_curves[] = {AEM_TLS_CURVES_HIGH};
static const int https_hashes[] = {AEM_TLS_HASHES_HIGH};

static char domain[AEM_MAXLEN_DOMAIN];
static size_t lenDomain;

int setDomain(const char * const newDomain, const size_t len) {
	if (len > AEM_MAXLEN_DOMAIN) return -1;

	lenDomain = len;
	memcpy(domain, newDomain, len);
	return 0;
}

__attribute__((warn_unused_result))
static bool isRequestValid(const char * const req, const size_t lenReq, bool * const keepAlive) {
	if (strcasestr(req, "\r\nConnection: close") != NULL) *keepAlive = false;

	if (lenReq < AEM_MINLEN_POST) return false;

	// First line
	if (strncmp(req, "POST /api/", 10) != 0) return false;
	for (int i = 10; i < 17; i++) {if (!islower(req[i])) return false;}
	if (req[17] != '/') return false;
	for (int i = 18; i < 24; i++) {if (!islower(req[i])) return false;}
	if (strncmp(req + 24, " HTTP/1.1\r\n", 11) != 0) return false;

	// Host header
	const char * const host = strstr(req, "\r\nHost: ");
	if (host == NULL) return false;
	if (strncmp(host + 8, domain, lenDomain) != 0) return false;
	if (strncmp(host + 8 + lenDomain, ":302\r\n", 6) != 0) return false;

	if (strstr(req, "\r\nContent-Length: 8266\r\n") == NULL) return false;

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

void tlsFree(void) {
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}

int tlsSetup(mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey) {
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_config_defaults failed: %d", ret); return -1;}

	mbedtls_ssl_conf_ca_chain(&conf, tlsCert->next, NULL);
	mbedtls_ssl_conf_ciphersuites(&conf, https_ciphersuites);
	mbedtls_ssl_conf_curves(&conf, https_curves);
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // Require TLS v1.2+
	mbedtls_ssl_conf_read_timeout(&conf, AEM_HTTPS_TIMEOUT);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_sig_hashes(&conf, https_hashes);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ctr_drbg_seed failed: %d", ret); return -1;}

	ret = mbedtls_ssl_conf_own_cert(&conf, tlsCert, tlsKey);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_conf_own_cert failed: %d", ret); return -1;}

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_setup failed: %d", ret); return -1;}

	return 0;
}

void respond_https(int sock) {
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
		unsigned char buf[AEM_HTTPS_POST_BOXED_SIZE];
		do {ret = mbedtls_ssl_read(&ssl, buf, AEM_MAXLEN_REQ + crypto_box_PUBLICKEYBYTES);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
		if (ret < 1) break;

		unsigned char * const postBegin = memmem(buf, ret, "\r\n\r\n", 4);
		if (postBegin == NULL) break;
		postBegin[3] = '\0';

		bool keepAlive = true;
		if (!isRequestValid((char*)buf, ret, &keepAlive)) break;

		size_t lenPost = ret - ((postBegin + 4) - buf);
		if (lenPost < crypto_box_PUBLICKEYBYTES) {
			int re2;
			do {re2 = mbedtls_ssl_read(&ssl, buf + ret, crypto_box_PUBLICKEYBYTES - lenPost);} while (re2 == MBEDTLS_ERR_SSL_WANT_READ);
			if (re2 < 1) break;

			lenPost += re2;
			if (lenPost < crypto_box_PUBLICKEYBYTES) break;
		}

		if (!pubkeyExists(postBegin + 4)) break;

		char url[AEM_LEN_URL_POST];
		memcpy(url, buf + AEM_SKIP_URL_POST, AEM_LEN_URL_POST);

		memmove(buf, postBegin + 4, lenPost);

		while (lenPost < AEM_HTTPS_POST_BOXED_SIZE) {
			do {ret = mbedtls_ssl_read(&ssl, buf + lenPost, AEM_HTTPS_POST_BOXED_SIZE - lenPost);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
			if (ret < 1) break;
			lenPost += ret;
		}
		if (ret < 1) break;

		if (https_post(&ssl, url, buf, keepAlive) != 0) break;

		explicit_bzero(buf, AEM_HTTPS_POST_BOXED_SIZE);
		if (!keepAlive) break;
	}

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
}
