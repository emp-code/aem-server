#define _GNU_SOURCE // for strcasestr

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
#include "Include/https_common.h"

#include "https.h"

#define AEM_MINLEN_GET 30 // GET / HTTP/1.1\r\nHost: a.bc\r\n\r\n
#define AEM_MAXLEN_REQ 800
#define AEM_HTTPS_TIMEOUT 30

static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static const int https_ciphersuites[] = {
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
0};

static const mbedtls_ecp_group_id https_curves[] = {
	MBEDTLS_ECP_DP_CURVE448,
	MBEDTLS_ECP_DP_CURVE25519,
	MBEDTLS_ECP_DP_SECP521R1,
	MBEDTLS_ECP_DP_SECP384R1,
MBEDTLS_ECP_DP_NONE};

static const int https_hashes[] = {
	MBEDTLS_SSL_HASH_SHA512,
MBEDTLS_MD_NONE};

static char req[AEM_MAXLEN_REQ + 1];

static unsigned char *html;
static size_t lenHtml = 0;

static char domain[AEM_MAXLEN_DOMAIN];
static size_t lenDomain;

int setDomain(const char * const src, const size_t len) {
	if (len > AEM_MAXLEN_DOMAIN) return -1;
	memcpy(domain, src, len);
	lenDomain = len;
	return 0;
}

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
		"Content-Length: %zd\r\n"
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

static void respond_robots(void) {
	sendData(&ssl,
		"HTTP/1.1 200 aem\r\n"
		"Cache-Control: public, max-age=9999999, immutable\r\n"
		"Connection: close\r\n"
		"Content-Length: 37\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Tk: N\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-Robots-Tag: noindex\r\n"
		"\r\n"
		"User-agent: *\n"
		"Disallow: /.well-known/"
	, 362);
}

// Tracking Status Resource for DNT
static void respond_tsr(void) {
	sendData(&ssl,
		"HTTP/1.1 200 aem\r\n"
		"Cache-Control: public, max-age=9999999, immutable\r\n"
		"Connection: close\r\n"
		"Content-Length: 17\r\n"
		"Content-Type: application/tracking-status+json\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Tk: N\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"\r\n"
		"{\"tracking\": \"N\"}"
	, 326);
}

static void handleRequest(const size_t lenReq) {
	if (lenReq < AEM_MINLEN_GET) return;
	if (memcmp(req, "GET /", 5) != 0) return;

	const char * const reqEnd = strstr(req, "\r\n\r\n");
	if (reqEnd == NULL) return;
	if (reqEnd + 4 != req + lenReq) return;

	// Host header
	const char * const host = strstr(req, "\r\nHost: ");
	if (host == NULL) return;
	if (strncmp(host + 8, "mta-sts.", 8) == 0) return respond_mtasts();
	if (strncmp(host + 8, domain, lenDomain) != 0) return;

	if (strncmp(req + 5, "robots.txt HTTP/1.1\r\n", 21) == 0) return respond_robots();
	if (strncmp(req + 5, ".well-known/dnt/ HTTP/1.1\r\n", 27) == 0) return respond_tsr();
	if (strncmp(req + 5, " HTTP/1.1\r\n", 11) != 0) return;

	// Forbidden request headers
	if (
		   (strcasestr(req, "\r\nAccess-Control-")   != NULL)
		|| (strcasestr(req, "\r\nAuthorization:")    != NULL)
		|| (strcasestr(req, "\r\nContent-Length:")   != NULL)
		|| (strcasestr(req, "\r\nCookie:")           != NULL)
		|| (strcasestr(req, "\r\nExpect:")           != NULL)
		|| (strcasestr(req, "\r\nOrigin:")           != NULL)
		|| (strcasestr(req, "\r\nRange:")            != NULL)
		|| (strcasestr(req, "\r\nX-Requested-With:") != NULL)
		|| (strcasestr(req, "\r\nSec-Fetch-Site: same-site") != NULL)
	) return;

	const char * const fetchMode = strcasestr(req, "\r\nSec-Fetch-Mode: ");
	if (fetchMode != NULL && strncasecmp(fetchMode + 18, "navigate\r\n", 10) != 0) return;

	const char * const fetchDest = strcasestr(req, "\r\nSec-Fetch-Dest: ");
	if (fetchDest != NULL && strncasecmp(fetchDest + 18, "document\r\n", 10) != 0) return;
}

void freeTls(void) {
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}

static int sni(void * const empty, mbedtls_ssl_context * const ssl, const unsigned char * const hostname, const size_t len) {
	if (empty != NULL || ssl == NULL) return -1;
	if (len == 0) return 0;

	return (hostname != NULL && (
	(len == lenDomain && memcmp(hostname, domain, lenDomain) == 0) ||
	(len == lenDomain + 8 && memcmp(hostname, "mta-sts.", 8) == 0 && memcmp(hostname + 8, domain, lenDomain) == 0)
	)) ? 0 : -1;
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
	mbedtls_ssl_conf_sni(&conf, sni, NULL);

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

	do {ret = mbedtls_ssl_read(&ssl, (unsigned char*)req, AEM_MAXLEN_REQ);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

	if (ret > 0) {
		req[ret] = '\0';
		handleRequest(ret);
	}

	explicit_bzero(req, AEM_MAXLEN_REQ);
	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
}
