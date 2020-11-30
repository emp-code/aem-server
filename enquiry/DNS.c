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

#include <sodium.h>

#include "DNS_protocol.h"

#include "DNS.h"

#define AEM_ENQUIRY

#include "../Common/tls_setup.c"

#define AEM_DNS_SERVER_ADDR "9.9.9.10" // Quad9 non-filtering | https://quad9.net
#define AEM_DNS_SERVER_HOST "dns.quad9.net"

#define AEM_DNS_SERVER_PORT "853" // DNS over TLS
#define AEM_DNS_BUFLEN 512

static int makeSocket(void) {
	const int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {syslog(LOG_ERR, "Failed socket(): %m"); return -1;}

	struct sockaddr_in myaddr;
	myaddr.sin_family = AF_INET;
	myaddr.sin_port = htons(853);
	inet_aton(AEM_DNS_SERVER_ADDR, &myaddr.sin_addr);

	if (connect(sock, &myaddr, sizeof(struct sockaddr_in)) != 0) {syslog(LOG_ERR, "Failed connect(): %m"); close(sock); return -1;}

	return sock;
}

static bool checkDnsLength(const unsigned char * const src, const int len) {
	uint16_t u;
	memcpy((unsigned char*)&u + 0, src + 1, 1);
	memcpy((unsigned char*)&u + 1, src + 0, 1);
	return (len == (int)u + 2);
}

uint32_t queryDns(const unsigned char * const domain, const size_t lenDomain, unsigned char * const mxDomain, int * const lenMxDomain) {
	if (domain == NULL || domain[0] == '\0' || lenDomain < 4 || mxDomain == NULL || lenMxDomain == NULL) return 0; // a.bc
	*lenMxDomain = 0;

	// Connect
	int sock = makeSocket();
	if (sock < 0) return 0;

	mbedtls_ssl_set_hostname(&ssl, AEM_DNS_SERVER_HOST);
	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	int ret;
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			syslog(LOG_ERR, "Failed TLS handshake: %x", -ret);
			mbedtls_ssl_close_notify(&ssl);
			mbedtls_ssl_session_reset(&ssl);
			return 0;
		}
	}

	const uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
	if (flags != 0) {
		syslog(LOG_ERR, "Failed verifying cert");
		mbedtls_ssl_close_notify(&ssl);
		mbedtls_ssl_session_reset(&ssl);
		return 0;
	}

	// DNS request (MX)
	size_t lenQuestion = 0;
	unsigned char question[256];

	uint16_t reqId;
	randombytes_buf(&reqId, 2);

	unsigned char req[100];
	bzero(req, 100);

	int reqLen = dnsCreateRequest(reqId, req, question, &lenQuestion, domain, lenDomain, AEM_DNS_RECORDTYPE_MX);

	do {ret = mbedtls_ssl_write(&ssl, req, reqLen);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	unsigned char res[AEM_DNS_BUFLEN];
	do {ret = mbedtls_ssl_read(&ssl, res, AEM_DNS_BUFLEN);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

	if (!checkDnsLength(res, ret)) {
		syslog(LOG_INFO, "DNS length mismatch");
		mbedtls_ssl_close_notify(&ssl);
		mbedtls_ssl_session_reset(&ssl);
		close(sock);
		return 0;
	}

	uint32_t ip = 0;
	if (dnsResponse_GetNameRecord(reqId, res + 2, ret - 2, question, lenQuestion, mxDomain, lenMxDomain, AEM_DNS_RECORDTYPE_MX) == 0 && *lenMxDomain > 4) { // a.bc
		randombytes_buf(&reqId, 2);
		bzero(req, 100);
		bzero(question, 256);
		lenQuestion = 0;
		reqLen = dnsCreateRequest(reqId, req, question, &lenQuestion, mxDomain, *lenMxDomain, AEM_DNS_RECORDTYPE_A);

		do {ret = mbedtls_ssl_write(&ssl, req, reqLen);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

		do {ret = mbedtls_ssl_read(&ssl, res, AEM_DNS_BUFLEN);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

		if (!checkDnsLength(res, ret)) {
			syslog(LOG_INFO, "DNS length mismatch");
			mbedtls_ssl_close_notify(&ssl);
			mbedtls_ssl_session_reset(&ssl);
			close(sock);
			return 0;
		}

		ip = dnsResponse_GetIp(reqId, res + 2, ret - 2, question, lenQuestion);
	}

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
	close(sock);
	return ip;
}

int getPtr(const uint32_t ip, unsigned char * const ptr, int * const lenPtr) {
	if (ip == 0 || ptr == NULL || lenPtr == NULL) return -1;

	// Connect
	int sock = makeSocket();
	if (sock < 0) return 0;

	mbedtls_ssl_set_hostname(&ssl, AEM_DNS_SERVER_HOST);
	mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	int ret;
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			syslog(LOG_ERR, "Failed TLS handshake: %x", -ret);
			mbedtls_ssl_close_notify(&ssl);
			mbedtls_ssl_session_reset(&ssl);
			return 0;
		}
	}

	const uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
	if (flags != 0) {
		syslog(LOG_ERR, "Failed verifying cert");
		mbedtls_ssl_close_notify(&ssl);
		mbedtls_ssl_session_reset(&ssl);
		return 0;
	}

	// DNS request (MX)
	size_t lenQuestion = 0;
	unsigned char question[256];

	uint16_t reqId;
	randombytes_buf(&reqId, 2);

	unsigned char req[100];
	bzero(req, 100);

	unsigned char reqDomain[100];
	sprintf((char*)reqDomain, "%u.%u.%u.%u.in-addr.arpa", ((uint8_t*)&ip)[3], ((uint8_t*)&ip)[2], ((uint8_t*)&ip)[1], ((uint8_t*)&ip)[0]);

	int reqLen = dnsCreateRequest(reqId, req, question, &lenQuestion, reqDomain, strlen((char*)reqDomain), AEM_DNS_RECORDTYPE_PTR);

	do {ret = mbedtls_ssl_write(&ssl, req, reqLen);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	unsigned char res[AEM_DNS_BUFLEN];
	do {ret = mbedtls_ssl_read(&ssl, res, AEM_DNS_BUFLEN);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_ssl_session_reset(&ssl);
	close(sock);

	if (!checkDnsLength(res, ret)) {
		syslog(LOG_INFO, "DNS length mismatch");
		return -1;
	}

	return dnsResponse_GetNameRecord(reqId, res + 2, ret - 2, question, lenQuestion, ptr, lenPtr, AEM_DNS_RECORDTYPE_PTR);
}
