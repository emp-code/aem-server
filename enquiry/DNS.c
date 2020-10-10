#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>

#include <sodium.h>

#include "DNS_protocol.h"

#define AEM_DNS_SERVER_ADDR "9.9.9.10" // Quad9 non-filtering | https://quad9.net
#define AEM_DNS_SERVER_HOST "dns.quad9.net"
#define AEM_DNS_SERVER_PORT "853" // DNS over TLS
#define AEM_DNS_BUFLEN 512

static mbedtls_ssl_config conf;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_x509_crt cacert;

void dns_freeTls(void) {
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_x509_crt_free(&cacert);
}

int dns_setupTls(void) {
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) return -1;
	if (mbedtls_x509_crt_parse_path(&cacert, "/ssl-certs/")) {syslog(LOG_ERR, "ssl-certs"); return -1;}
	if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) return -1;

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_dhm_min_bitlen(&conf, 2048); // Minimum length for DH parameters
	mbedtls_ssl_conf_fallback(&conf, MBEDTLS_SSL_IS_NOT_FALLBACK);
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // Require TLS v1.2+
	mbedtls_ssl_conf_renegotiation(&conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
	return 0;
}

static int makeSocket(void) {
	const int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {syslog(LOG_ERR, "Failed socket(): %m"); return -1;}

	struct addrinfo hints;
	struct addrinfo *res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(AEM_DNS_SERVER_ADDR, AEM_DNS_SERVER_PORT, &hints, &res) != 0) {syslog(LOG_ERR, "Failed getaddrinfo()"); return -1;}

	if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {syslog(LOG_ERR, "Failed connect: %m"); free(res); return -1;}

	free(res);
	return sock;
}

uint32_t queryDns(const unsigned char * const domain, const size_t lenDomain) {
	if (domain == NULL || domain[0] == '\0' || lenDomain < 4) return 0; // a.bc

	// Connect
	int sock = makeSocket();
	if (sock < 0) return 0;

	mbedtls_ssl_context ssl;
	mbedtls_ssl_init(&ssl);
	if (mbedtls_ssl_setup(&ssl, &conf) != 0) {syslog(LOG_ERR, "Failed setting up TLS"); return 0;}
	if (mbedtls_ssl_set_hostname(&ssl, AEM_DNS_SERVER_HOST) != 0) {syslog(LOG_ERR, "Failed setting hostname"); return 0;}
	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	int ret;
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {syslog(LOG_ERR, "Failed TLS handshake: %x", -ret); return 0;}
	}

	const uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
	if (flags != 0) {syslog(LOG_ERR, "Failed verifying cert"); return 0;}

	// DNS request (MX)
	unsigned char req[100];
	bzero(req, 100);
	int reqLen = dnsCreateRequest(req, domain, lenDomain, true);

	do {ret = mbedtls_ssl_write(&ssl, req, reqLen);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	unsigned char res[AEM_DNS_BUFLEN];
	do {ret = mbedtls_ssl_read(&ssl, res, AEM_DNS_BUFLEN);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

	// First two bytes in TCP DNS messages store length 	// TODO: Check length
	memmove(res, res + 2, ret - 2);
	ret -= 2;

	unsigned char mxDomain[256];
	int lenMxDomain = 0;
	uint32_t ip = 0;
	if (dnsResponse_GetMx(res, ret, mxDomain, &lenMxDomain) == 0 && lenMxDomain > 4) { // a.bc
		syslog(LOG_INFO, "mx=%.*s;", lenMxDomain, mxDomain);

		bzero(req, 100);
		reqLen = dnsCreateRequest(req, mxDomain, lenMxDomain, false);

		do {ret = mbedtls_ssl_write(&ssl, req, reqLen);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

		do {ret = mbedtls_ssl_read(&ssl, res, AEM_DNS_BUFLEN);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

		// First two bytes in TCP DNS messages store length 	// TODO: Check length
		memmove(res, res + 2, ret - 2);
		ret -= 2;

		ip = dnsResponse_GetIp(res, ret);
	}

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_free(&ssl);
	close(sock);

	return ip;
}
