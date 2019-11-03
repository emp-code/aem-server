#define _GNU_SOURCE // for memmem, strcasestr

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "https.h"

#include "global.h"
#include "https_get.h"

#define AEM_MINLEN_GET 30 // GET / HTTP/1.1\r\nHost: a.bc\r\n\r\n
#define AEM_MAXLEN_REQ 800
#define AEM_MAXLEN_URL 25
#define AEM_HTTPS_TIMEOUT 30

#define AEM_SKIP_URL_GET 5 // 'GET /'

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

__attribute__((warn_unused_result))
static bool supportsBrotli(const char * const req) {
	const char * const ae = strcasestr(req, "\r\nAccept-Encoding: ");
	if (ae == NULL) return false;

	const char * const aeEnd = strpbrk(ae + 19, "\r\n");
	const char * const br = strcasestr(ae + 19, "br");
	if (br == NULL || br > aeEnd) return false;

	if (br[2] != ',' && br[2] != ' ' && br[2] != '\r') return false;

	const char br1 = ae[br - ae - 1]; // br - 1
	if (br1 != ',' && br1 != ' ') return false;

	return true;
}

static void handleRequest(char * const req, size_t lenReq) {
	if (lenReq < AEM_MINLEN_GET) return;
	if (memcmp(req, "GET /", 5) != 0) return;

	char * const reqEnd = memmem(req, lenReq, "\r\n\r\n", 4);
	if (reqEnd == NULL) return;

	lenReq = reqEnd - req + 2; // Include \r\n at end
	if (memchr(req, '\0', lenReq) != NULL) return;
	reqEnd[2] = '\0';

	// Host header
	const char * const host = strstr(req, "\r\nHost: ");
	if (host == NULL) return;
	if (strncmp(host + 8, "mta-sts.", 8) == 0) return https_mtasts(&ssl);
	if (strncmp(host + 8, domain, lenDomain) != 0) return;

	// Protocol: only HTTP/1.1 is supported
	const char * const firstCrLf = strpbrk(req, "\r\n");
	const char * const prot = strstr(req, " HTTP/1.1\r\n");
	if (prot == NULL || prot > firstCrLf) return;

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
		|| (strcasestr(req, "\r\nSec-Fetch-Mode: cors")       != NULL)
		|| (strcasestr(req, "\r\nSec-Fetch-Mode: websocket")  != NULL)
		|| (strcasestr(req, "\r\nSec-Fetch-Site: cross-site") != NULL)
		|| (strcasestr(req, "\r\nSec-Fetch-Site: same-site")  != NULL)
	) return;

	if (memcmp(req + 5, "robots.txt ", 11) == 0) return https_robots(&ssl);
	if (memcmp(req + 5, ".well-known/dnt/", 16) == 0) return https_tsr(&ssl);

	if (!supportsBrotli(req)) return;

	const char * const urlEnd = strchr(req + AEM_SKIP_URL_GET, ' ');
	if (urlEnd == NULL) return;

	const size_t lenUrl = urlEnd - (req + AEM_SKIP_URL_GET);
	if (lenUrl > AEM_MAXLEN_URL) return;

	https_respond(&ssl, req + AEM_SKIP_URL_GET, lenUrl);
}

void tlsFree(void) {
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}

static int sni(void *parameter, mbedtls_ssl_context *ssl, const unsigned char *hostname, size_t len) {
	if (parameter != NULL || ssl == NULL) return -1;
	if (len == 0) return 0;

	return (hostname == NULL || len != lenDomain || memcmp(hostname, domain, lenDomain) != 0) ? -1 : 0;
}

int tlsSetup(mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey) {
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		printf("mbedtls_ssl_config_defaults returned %d\n", ret);
		return -1;
	}

	mbedtls_ssl_conf_ca_chain(&conf, tlsCert->next, NULL);
	mbedtls_ssl_conf_ciphersuites(&conf, https_ciphersuites);
	mbedtls_ssl_conf_curves(&conf, https_curves);
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // Require TLS v1.2+
	mbedtls_ssl_conf_read_timeout(&conf, AEM_HTTPS_TIMEOUT);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_sig_hashes(&conf, https_hashes);
	mbedtls_ssl_conf_sni(&conf, sni, NULL);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret != 0) {
		printf("mbedtls_ctr_drbg_seed returned %d\n", ret);
		return -1;
	}

	ret = mbedtls_ssl_conf_own_cert(&conf, tlsCert, tlsKey);
	if (ret != 0) {
		printf("mbedtls_ssl_conf_own_cert returned %d\n", ret);
		return -1;
	}

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {
		printf("mbedtls_ssl_setup returned %d\n", ret);
		return -1;
	}

	return 0;
}

void respond_https(int sock) {
	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	int ret;
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			printf("mbedtls_ssl_handshake returned %d\n", ret);
			mbedtls_ssl_close_notify(&ssl);
			mbedtls_ssl_session_reset(&ssl);
			return;
		}
	}

	unsigned char * const req = malloc(AEM_MAXLEN_REQ + 1);

	int lenReq;
	do {lenReq = mbedtls_ssl_read(&ssl, req, AEM_MAXLEN_REQ);} while (lenReq == MBEDTLS_ERR_SSL_WANT_READ);

	if (lenReq > 0) {
		req[lenReq] = '\0';
		handleRequest((char*)req, lenReq);
	}

	free(req);
	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
}
