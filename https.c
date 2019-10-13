#define _GNU_SOURCE // for memmem, strcasestr

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h> // for islower

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "aem_file.h"

#include "https_get.h"
#include "https_post.h"

#include "https.h"

#define AEM_MAXLEN_URL 25
#define AEM_HTTPS_TIMEOUT 30

#define AEM_SKIP_URL_GET 5 // 'GET /'
#define AEM_SKIP_URL_POST 10 // 'POST /api/'

#define AEM_HTTPS_REQUEST_INVALID -1
#define AEM_HTTPS_REQUEST_GET 0
#define AEM_HTTPS_REQUEST_POST 1
#define AEM_HTTPS_REQUEST_MTASTS 10
#define AEM_HTTPS_REQUEST_ROBOTS 20
#define AEM_HTTPS_REQUEST_PUBKEY 50

static const int https_ciphersuites[] = {
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
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

	if (*(br + 2) != ',' && *(br + 2) != ' ' && *(br + 2) != '\r') return false;

	const char * const br1 = ae + (br - ae - 1); // br - 1
	if (*br1 != ',' && *br1 != ' ') return false;

	return true;
}

__attribute__((warn_unused_result))
static int getRequestType(char * const req, size_t lenReq, const char * const domain, const size_t lenDomain) {
	if (lenReq < 30) return AEM_HTTPS_REQUEST_INVALID; // GET / HTTP/1.1\r\nHost: a.bc\r\n\r\n

	char * const reqEnd = memmem(req, lenReq, "\r\n\r\n", 4);
	if (reqEnd == NULL) return AEM_HTTPS_REQUEST_INVALID;

	lenReq = reqEnd - req + 2; // Include \r\n at end
	if (memchr(req, '\0', lenReq) != NULL) return AEM_HTTPS_REQUEST_INVALID;
	reqEnd[2] = '\0';

	// Host header
	const char * const host = strstr(req, "\r\nHost: ");
	if (host == NULL) return AEM_HTTPS_REQUEST_INVALID;
	if (strncmp(host + 8, "mta-sts.", 8) == 0) return AEM_HTTPS_REQUEST_MTASTS;
	if (strncmp(host + 8, domain, lenDomain) != 0) return AEM_HTTPS_REQUEST_INVALID;

	// Protocol: only HTTP/1.1 is supported
	const char * const firstCrLf = strpbrk(req, "\r\n");
	const char * const prot = strstr(req, " HTTP/1.1\r\n");
	if (prot == NULL || prot > firstCrLf) return AEM_HTTPS_REQUEST_INVALID;

	// Forbidden request headers
	if (
		   (strcasestr(req, "\r\nAuthorization:") != NULL)
		|| (strcasestr(req, "\r\nCookie:") != NULL)
		|| (strcasestr(req, "\r\nExpect:") != NULL)
		|| (strcasestr(req, "\r\nRange:")  != NULL)
		|| (strcasestr(req, "\r\nSec-Fetch-Site: same-site") != NULL)
		// These are only for preflighted requests, which All-Ears doesn't use
		|| (strcasestr(req, "\r\nAccess-Control-Request-Method:")  != NULL)
		|| (strcasestr(req, "\r\nAccess-Control-Request-Headers:") != NULL)
	) return AEM_HTTPS_REQUEST_INVALID;

	if (memcmp(req, "GET /", 5) == 0) {
		if (
			   (strcasestr(req, "\r\nSec-Fetch-Mode: cors")       != NULL)
			|| (strcasestr(req, "\r\nSec-Fetch-Mode: websocket")  != NULL)
			|| (strcasestr(req, "\r\nSec-Fetch-Site: cross-site") != NULL)
			|| (strcasestr(req, "\r\nContent-Length:")   != NULL)
			|| (strcasestr(req, "\r\nOrigin:")           != NULL)
			|| (strcasestr(req, "\r\nX-Requested-With:") != NULL)
		) return AEM_HTTPS_REQUEST_INVALID;

		if (!supportsBrotli(req)) return AEM_HTTPS_REQUEST_INVALID;

		if (memcmp(req + 5, "api/pubkey ", 11) == 0) return AEM_HTTPS_REQUEST_PUBKEY;
		if (memcmp(req + 5, "robots.txt ", 11) == 0) return AEM_HTTPS_REQUEST_ROBOTS;

		return AEM_HTTPS_REQUEST_GET;
	}

	if (memcmp(req, "POST /api/", 10) == 0) {
		if (lenReq < 71) return AEM_HTTPS_REQUEST_INVALID; // POST /api/account/browse HTTP/1.1\r\nHost: a.bc\r\nContent-Length: 8264\r\n\r\n
		for (int i = 10; i < 17; i++) {if (!islower(req[i])) return AEM_HTTPS_REQUEST_INVALID;}
		if (req[17] != '/') return AEM_HTTPS_REQUEST_INVALID;
		for (int i = 18; i < 24; i++) {if (!islower(req[i])) return AEM_HTTPS_REQUEST_INVALID;}
		if (memcmp(req + 24, " HTTP/1.1\r\n", 11) != 0) return AEM_HTTPS_REQUEST_INVALID;

		const char * const cl = strstr(req, "\r\nContent-Length: 8264\r\n");
		if (cl == NULL) return AEM_HTTPS_REQUEST_INVALID;

		reqEnd[2] = '\r';
		return AEM_HTTPS_REQUEST_POST;
	}

	return AEM_HTTPS_REQUEST_INVALID;
}

void handleGet(mbedtls_ssl_context * const ssl, char * const buf, const char * const domain, const size_t lenDomain, const struct aem_fileSet * const fileSet) {
	const char * const urlEnd = strchr(buf + AEM_SKIP_URL_GET, ' ');
	if (urlEnd == NULL) return;

	const size_t lenUrl = urlEnd - (buf + AEM_SKIP_URL_GET);
	if (lenUrl > AEM_MAXLEN_URL) return;

	https_get(ssl, buf + AEM_SKIP_URL_GET, lenUrl, fileSet, domain, lenDomain);
}

void handlePost(mbedtls_ssl_context * const ssl, char * const buf, const size_t lenReq, const unsigned char * const ssk, const unsigned char * const addrKey) {
	const char * const urlEnd = strchr(buf + AEM_SKIP_URL_POST, ' ');
	if (urlEnd == NULL) return;
	const size_t lenUrl = urlEnd - (buf + AEM_SKIP_URL_POST);

	char url[lenUrl];
	memcpy(url, buf + AEM_SKIP_URL_POST, lenUrl);

	const char *post = strstr(buf + 20, "\r\n\r\n");
	if (post == NULL) return;
	post += 4;

	size_t lenPost = lenReq - (post - buf);
	if (lenPost > 0) memmove(buf, post, lenPost);

	while (lenPost < AEM_HTTPS_POST_BOXED_SIZE) {
		int ret;
		do {ret = mbedtls_ssl_read(ssl, (unsigned char*)(buf + lenPost), AEM_HTTPS_POST_BOXED_SIZE - lenPost);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
		if (ret < 0) return;
		lenPost += ret;
	}

	https_post(ssl, ssk, addrKey, url, (unsigned char*)buf);
}

static void tlsFree(mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf, mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg) {
	mbedtls_ssl_free(ssl);
	mbedtls_ssl_config_free(conf);
	mbedtls_entropy_free(entropy);
	mbedtls_ctr_drbg_free(ctr_drbg);
}

void respond_https(int sock, mbedtls_x509_crt * const srvcert, mbedtls_pk_context * const pkey, const unsigned char * const ssk, const unsigned char * const addrKey, const char * const domain, const size_t lenDomain, const struct aem_fileSet * const fileSet) {
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		printf("[HTTPS] mbedtls_ssl_config_defaults returned %d\n", ret);
		tlsFree(&ssl, &conf, &entropy, &ctr_drbg);
		return;
	}

	mbedtls_ssl_conf_ca_chain(&conf, srvcert->next, NULL);
	mbedtls_ssl_conf_ciphersuites(&conf, https_ciphersuites);
	mbedtls_ssl_conf_curves(&conf, https_curves);
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // Require TLS v1.2+
	mbedtls_ssl_conf_read_timeout(&conf, AEM_HTTPS_TIMEOUT);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_sig_hashes(&conf, https_hashes);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char*)"All-Ears Mail HTTPS", 19);
	if (ret != 0) {
		printf("[HTTPS] mbedtls_ctr_drbg_seed returned %d\n", ret);
		tlsFree(&ssl, &conf, &entropy, &ctr_drbg);
		return;
	}

	ret = mbedtls_ssl_conf_own_cert(&conf, srvcert, pkey);
	if (ret != 0) {
		printf("[HTTPS] mbedtls_ssl_conf_own_cert returned %d\n", ret);
		tlsFree(&ssl, &conf, &entropy, &ctr_drbg);
		return;
	}

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {
		printf("[HTTPS] mbedtls_ssl_setup returned %d\n", ret);
		tlsFree(&ssl, &conf, &entropy, &ctr_drbg);
		return;
	}

	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	// Handshake
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			printf("[HTTPS] mbedtls_ssl_handshake returned %d\n", ret);
			tlsFree(&ssl, &conf, &entropy, &ctr_drbg);
			return;
		}
	}

	unsigned char * const req = malloc(AEM_HTTPS_POST_BOXED_SIZE);

	int lenReq;
	do {lenReq = mbedtls_ssl_read(&ssl, req, AEM_HTTPS_POST_BOXED_SIZE - 1);} while (lenReq == MBEDTLS_ERR_SSL_WANT_READ);

	if (lenReq > 0) {
		req[lenReq] = '\0';
		const int reqType = getRequestType((char*)req, lenReq, domain, lenDomain);
		if (reqType == AEM_HTTPS_REQUEST_GET) handleGet(&ssl, (char*)req, domain, lenDomain, fileSet);
		else if (reqType == AEM_HTTPS_REQUEST_POST) handlePost(&ssl, (char*)req, lenReq, ssk, addrKey);
		else if (reqType == AEM_HTTPS_REQUEST_MTASTS) https_mtasts(&ssl, domain, lenDomain);
		else if (reqType == AEM_HTTPS_REQUEST_ROBOTS) https_robots(&ssl);
		else if (reqType == AEM_HTTPS_REQUEST_PUBKEY) https_pubkey(&ssl, ssk);
	}

	free(req);
	tlsFree(&ssl, &conf, &entropy, &ctr_drbg);
}
