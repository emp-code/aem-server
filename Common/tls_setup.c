static unsigned char *tlsCrt_data;
static unsigned char *tlsKey_data;

static mbedtls_x509_crt tlsCrt;
static mbedtls_pk_context tlsKey;

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

__attribute__((warn_unused_result))
static int getDomainFromCert(void) {
	char certInfo[1024];
	mbedtls_x509_crt_info(certInfo, 1024, "AEM_", &tlsCrt);

	const char *c = strstr(certInfo, "\nAEM_subject name");
	if (c == NULL) return -1;
	c += 17;

	const char * const end = strchr(c, '\n');

	c = strstr(c, ": CN=");
	if (c == NULL || c > end) return -1;
	c += 5;

	const int len = end - c;
	if (len > AEM_MAXLEN_DOMAIN) return -1;

	memcpy(domain, c, len);
	lenDomain = len;
	return 0;
}

int setCertData(unsigned char * const crtData, const size_t crtLen, unsigned char * const keyData, const size_t keyLen) {
	tlsCrt_data = crtData;
	tlsKey_data = keyData;

	mbedtls_x509_crt_init(&tlsCrt);
	int ret = mbedtls_x509_crt_parse(&tlsCrt, crtData, crtLen);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_x509_crt_parse failed: %d", ret); return -1;}

	mbedtls_pk_init(&tlsKey);
	ret = mbedtls_pk_parse_key(&tlsKey, keyData, keyLen, NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_pk_parse_key failed: %d", ret); return -1;}

	if (getDomainFromCert() != 0) {syslog(LOG_ERR, "Failed getting domain from certificate"); return -1;}
	return 0;
}

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

int tlsSetup(void) {
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

	ret = mbedtls_ssl_conf_own_cert(&conf, &tlsCrt, &tlsKey);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_conf_own_cert failed: %d", ret); return -1;}

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_setup failed: %d", ret); return -1;}

	sodium_free(tlsCrt_data);
	sodium_free(tlsKey_data);
	return 0;
}

void tlsFree(void) {
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_x509_crt_free(&tlsCrt);
	mbedtls_pk_free(&tlsKey);
}
