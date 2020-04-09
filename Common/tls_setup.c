static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

#include "../Common/tls_suites.h"
#ifdef AEM_MTA
static const int tls_ciphersuites[] = {AEM_TLS_CIPHERSUITES_MTA};
#else
static const int tls_ciphersuites[] = {AEM_TLS_CIPHERSUITES_HIGH};
static const mbedtls_ecp_group_id tls_curves[] = {AEM_TLS_CURVES_HIGH};
static const int tls_hashes[] = {AEM_TLS_HASHES_HIGH};
#endif

#ifdef AEM_MTA
__attribute__((warn_unused_result))
static uint8_t getTlsVersion(const mbedtls_ssl_context * const tls) {
	if (tls == NULL) return 0;

	const char * const c = mbedtls_ssl_get_version(tls);
	if (c == NULL || strlen(c) != 7 || memcmp(c, "TLSv1.", 6) != 0) return 0;

	switch(c[6]) {
		case '0': return 1;
		case '1': return 2;
		case '2': return 3;
		case '3': return 4;
	}

	return 0;
}
#else
static int sni(void * const empty, mbedtls_ssl_context * const ssl2, const unsigned char * const hostname, const size_t len) {
	if (empty != NULL || ssl2 != &ssl) return -1;
	if (len == 0) return 0;

	return (hostname != NULL && (
	(len == lenDomain && memcmp(hostname, domain, lenDomain) == 0) ||
	(len == lenDomain + 8 && memcmp(hostname, "mta-sts.", 8) == 0 && memcmp(hostname + 8, domain, lenDomain) == 0)
	)) ? 0 : -1;
}
#endif

int tlsSetup(mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey) {
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_config_defaults failed: %d", ret); return -1;}

#ifdef AEM_MTA
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1); // Require TLS v1.0+
#else // API/Web
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // Require TLS v1.2+
	mbedtls_ssl_conf_curves(&conf, tls_curves);
	mbedtls_ssl_conf_sig_hashes(&conf, tls_hashes);
	mbedtls_ssl_conf_sni(&conf, sni, NULL);
#endif

	mbedtls_ssl_conf_ciphersuites(&conf, tls_ciphersuites);
	mbedtls_ssl_conf_read_timeout(&conf, AEM_CLIENT_TIMEOUT);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ctr_drbg_seed failed: %d", ret); return -1;}

	ret = mbedtls_ssl_conf_own_cert(&conf, tlsCert, tlsKey);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_conf_own_cert failed: %d", ret); return -1;}

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_setup failed: %d", ret); return -1;}

	return 0;
}

void tlsFree(void) {
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}
