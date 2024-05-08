#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>

#include "../Global.h"
#include "../Common/memeq.h"
#include "../Common/x509_getCn.h"

#ifdef AEM_MTA
static unsigned char ourDomain[AEM_MAXLEN_OURDOMAIN];
static size_t lenOurDomain;
#endif

static mbedtls_x509_crt tlsCrt;
static mbedtls_pk_context tlsKey;

static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

#if defined(AEM_API_SMTP) || defined(AEM_ENQUIRY)
static mbedtls_x509_crt cacert;
#endif

#include "../Common/tls_suites.h"
#ifdef AEM_MTA
static const int tls_ciphersuites[] = {AEM_TLS_CIPHERSUITES_MTA};
#elif defined(AEM_API_SMTP)
static const int tls_ciphersuites[] = {AEM_TLS_CIPHERSUITES_OUT};
static const mbedtls_ecp_group_id tls_curves[] = {AEM_TLS_CURVES_OUT};
static const int tls_hashes[] = {AEM_TLS_HASHES_OUT};
#else
static const int tls_ciphersuites[] = {AEM_TLS_CIPHERSUITES_HIGH};
static const mbedtls_ecp_group_id tls_curves[] = {AEM_TLS_CURVES_HIGH};
static const int tls_hashes[] = {AEM_TLS_HASHES_HIGH};
#endif

#if defined(AEM_MTA) || defined(AEM_API_SMTP)
#define AEM_TLS_MINOR MBEDTLS_SSL_MINOR_VERSION_1 // TLS v1.0+
#else
#define AEM_TLS_MINOR MBEDTLS_SSL_MINOR_VERSION_3 // TLS v1.2+
#endif

#if defined(AEM_MTA) || defined(AEM_API_SMTP)
__attribute__((warn_unused_result))
static uint8_t getTlsVersion(const mbedtls_ssl_context * const tls) {
	if (tls == NULL) return 0;
	const char * const c = mbedtls_ssl_get_version(tls);
	return (c == NULL || !memeq_anycase(c, "TLSv1.", 6) || c[6] < '0' || c[6] > '3') ? 0 : c[6] - '0';
}
#endif

#if defined(AEM_API_HTTP) || defined(AEM_WEB)
static int sni(void * const empty, mbedtls_ssl_context * const ssl2, const unsigned char * const hostname, const size_t len) {
	if (empty != NULL || ssl2 != &ssl) return -1;
	if (len == 0) return 0;

	return (hostname != NULL && ((len == AEM_DOMAIN_LEN && memeq(hostname, AEM_DOMAIN, AEM_DOMAIN_LEN))
#ifdef AEM_WEB
	|| (len == AEM_DOMAIN_LEN + 8 && memeq(hostname, "mta-sts.", 8) && memeq(hostname + 8, AEM_DOMAIN, AEM_DOMAIN_LEN))
#endif
	)) ? 0 : -1;
}
#endif

#ifdef AEM_API_SMTP
int tlsSetup_sendmail(void) {
#elifdef AEM_MTA
int tlsSetup(const unsigned char * const tls_crt_data, const size_t tls_crt_size, const unsigned char * const tls_key_data, const size_t tls_key_size) {
#else
int tlsSetup(void) {
#endif

#ifdef AEM_MTA
	size_t lenIssuer;
	const unsigned char * const issuer = x509_getCn(tls_crt_data, tls_crt_size, &lenIssuer);
	if (issuer == NULL) return -1;

	size_t lenSubject;
	const unsigned char * const subject = x509_getCn(issuer, tls_crt_data + tls_crt_size - issuer, &lenSubject);
	if (subject == NULL || lenSubject > AEM_MAXLEN_OURDOMAIN) return -1;

	lenOurDomain = lenSubject;
	memcpy(ourDomain, subject, lenSubject);
#endif

	mbedtls_x509_crt_init(&tlsCrt);
	int ret = mbedtls_x509_crt_parse_der(&tlsCrt, tls_crt_data, tls_crt_size);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_x509_crt_parse failed: %x", -ret); return -1;}

	mbedtls_pk_init(&tlsKey);
	ret = mbedtls_pk_parse_key(&tlsKey, tls_key_data, tls_key_size, NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_pk_parse_key failed: %x", -ret); return -1;}

	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(AEM_API_SMTP) || defined(AEM_ENQUIRY)
	ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
#else
	ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
#endif
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_config_defaults failed: %x", -ret); return -1;}

#ifdef AEM_MTA
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
#else
	mbedtls_ssl_conf_curves(&conf, tls_curves);
	mbedtls_ssl_conf_sig_hashes(&conf, tls_hashes);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
#endif

#if defined(AEM_API_HTTP) || defined(AEM_WEB)
	mbedtls_ssl_conf_dhm_min_bitlen(&conf, 2048);
	mbedtls_ssl_conf_sni(&conf, sni, NULL);
#endif

#if defined(AEM_API_SMTP) || defined(AEM_ENQUIRY)
	mbedtls_x509_crt_init(&cacert);
	ret = mbedtls_x509_crt_parse_path(&cacert, "/ssl-certs/");
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_x509_crt_parse_path failed: %x", -ret); return -1;}
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
#endif

	mbedtls_ssl_conf_ciphersuites(&conf, tls_ciphersuites);
	mbedtls_ssl_conf_fallback(&conf, MBEDTLS_SSL_IS_NOT_FALLBACK);
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, AEM_TLS_MINOR);
	mbedtls_ssl_conf_read_timeout(&conf, AEM_TLS_TIMEOUT);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ctr_drbg_seed failed: %x", -ret); return -1;}

	ret = mbedtls_ssl_conf_own_cert(&conf, &tlsCrt, &tlsKey);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_conf_own_cert failed: %x", -ret); return -1;}

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_setup failed: %x", -ret); return -1;}

	return 0;
}

#ifdef AEM_API_SMTP
void tlsFree_sendmail(void) {
#else
void tlsFree(void) {
#endif
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_x509_crt_free(&tlsCrt);
	mbedtls_pk_free(&tlsKey);
}
