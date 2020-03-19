#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "Include/Brotli.h"
#include "Include/QuotedPrintable.h"
#include "Include/ToUtf8.h"
#include "Include/Trim.h"

#include "delivery.h"
#include "processing.h"

#include "smtp.h"

#include "../Global.h"

#define AEM_MAXLEN_DOMAIN 32

#define AEM_SMTP_SIZE_CMD 512 // RFC5321: min. 512

#define AEM_SMTP_MAX_ADDRSIZE 200
#define AEM_SMTP_MAX_ADDRSIZE_TO 4096 // RFC5321: must accept 100 recipients at minimum

#define AEM_SMTP_SIZE_BODY 262144 // RFC5321: min. 64k; XXX if changed, set the HLO responses and their lengths below also

#define AEM_EHLO_RESPONSE_LEN 61
#define AEM_EHLO_RESPONSE \
"\r\n250-SIZE 262144" \
"\r\n250-STARTTLS" \
"\r\n250-8BITMIME" \
"\r\n250 SMTPUTF8" \
"\r\n"

#define AEM_SHLO_RESPONSE_LEN 47
#define AEM_SHLO_RESPONSE \
"\r\n250-SIZE 262144" \
"\r\n250-8BITMIME" \
"\r\n250 SMTPUTF8" \
"\r\n"

static const int smtp_ciphersuites[] = {
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
MBEDTLS_TLS_RSA_WITH_AES_256_CCM,
MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8,
MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
MBEDTLS_TLS_RSA_WITH_AES_128_CCM,
MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8,
MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
MBEDTLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384,
MBEDTLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256,
MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
MBEDTLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384,
MBEDTLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
MBEDTLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
MBEDTLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
MBEDTLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
MBEDTLS_TLS_ECDH_RSA_WITH_RC4_128_SHA,
MBEDTLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
MBEDTLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
MBEDTLS_TLS_RSA_WITH_RC4_128_SHA,
MBEDTLS_TLS_RSA_WITH_RC4_128_MD5,
0};

static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static size_t lenDomain;
static char domain[AEM_MAXLEN_DOMAIN];

int setDomain(const char * const new, const size_t len) {
	if (lenDomain > AEM_MAXLEN_DOMAIN) return -1;

	lenDomain = len;
	memcpy(domain, new, len);
	return 0;
}

__attribute__((warn_unused_result))
static int recv_aem(const int sock, mbedtls_ssl_context * const tls, char * const buf, const size_t maxSize) {
	if (buf == NULL || maxSize < 1) return -1;

	if (tls != NULL) {
		int ret;
		do {ret = mbedtls_ssl_read(tls, (unsigned char*)buf, maxSize);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
		return ret;
	}

	if (sock > 0) return recv(sock, buf, maxSize, 0);

	return -1;
}

__attribute__((warn_unused_result))
static bool send_aem(const int sock, mbedtls_ssl_context * const tls, const char * const data, const size_t lenData) {
	if (data == NULL || lenData < 1) return false;

	if (tls != NULL) {
		size_t sent = 0;

		while (sent < lenData) {
			int ret;
			do {ret = mbedtls_ssl_write(tls, (const unsigned char*)(data + sent), lenData - sent);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
			if (ret < 0) return false;

			sent += ret;
		}

		return true;
	}

	if (sock > 0) return (send(sock, data, lenData, 0) == (ssize_t)lenData);

	return false;
}

static bool smtp_respond(const int sock, mbedtls_ssl_context * const tls, const char code1, const char code2, const char code3) {
	const char resp[9] = {code1, code2, code3, ' ', 'a', 'e', 'm', '\r', '\n'};
	return send_aem(sock, tls, resp, 9);
}

__attribute__((warn_unused_result))
static size_t smtp_addr_sender(const char * const buf, const size_t len, char * const addr) {
	if (buf == NULL || len < 1 || addr == NULL) return 0;

	size_t skipBytes = 0;
	while (isspace(buf[skipBytes]) && skipBytes < len) skipBytes++;
	if (skipBytes >= len) return 0;

	if (buf[skipBytes] != '<') return 0;
	skipBytes++;

	const size_t max = len - skipBytes - 1;
	size_t lenAddr = 0;
	while (lenAddr < max && buf[skipBytes + lenAddr] != '>') lenAddr++;

	if (lenAddr < 1 || lenAddr > AEM_SMTP_MAX_ADDRSIZE) return 0;

	memcpy(addr, buf + skipBytes, lenAddr);
	return lenAddr;
}

__attribute__((warn_unused_result))
static size_t smtp_addr_our(const char * const buf, const size_t len, char * const addr) {
	if (buf == NULL || len < 1 || addr == NULL) return 0;

	size_t skipBytes = 0;
	while (isspace(buf[skipBytes]) && skipBytes < len) skipBytes++;
	if (skipBytes >= len) return 0;

	if (buf[skipBytes] != '<') return 0;
	skipBytes++;

	const int max = len - skipBytes - 1;
	int lenAddr = 0;
	while (lenAddr < max && buf[skipBytes + lenAddr] != '>') lenAddr++;

	if (lenAddr < 1) return 0;

	int addrChars = 0;
	for (int i = 0; i < lenAddr; i++) {
		if (isalnum(buf[skipBytes + i])) {
			if (addrChars + 1 > AEM_MAXLEN_ADDR32) return 0;
			addr[addrChars] = tolower(buf[skipBytes + i]);
			addrChars++;
		} else if (buf[skipBytes + i] == '@') {
			if (lenAddr - i - 1 != (int)lenDomain || strncasecmp(buf + skipBytes + i + 1, domain, lenDomain) != 0) return 0;
			break;
		}
	}

	return addrChars;
}

__attribute__((warn_unused_result))
static bool smtp_greet(const int sock) {
	const int lenGreet = 6 + lenDomain;
	char ourGreeting[lenGreet];
	memcpy(ourGreeting, "220 ", 4);
	memcpy(ourGreeting + 4, domain, lenDomain);
	memcpy(ourGreeting + 4 + lenDomain, "\r\n", 2);
	return (send(sock, ourGreeting, lenGreet, 0) == lenGreet);
}

__attribute__((warn_unused_result))
static bool smtp_shlo(mbedtls_ssl_context * const tls) {
	if (tls == NULL) return false;

	const ssize_t lenShlo = 4 + lenDomain + AEM_SHLO_RESPONSE_LEN;
	char shlo[lenShlo];
	memcpy(shlo, "250-", 4);
	memcpy(shlo + 4, domain, lenDomain);
	memcpy(shlo + 4 + lenDomain, AEM_SHLO_RESPONSE, AEM_SHLO_RESPONSE_LEN);
	return send_aem(0, tls, shlo, lenShlo);
}

__attribute__((warn_unused_result))
static bool smtp_helo(const int sock, const char * const buf, const ssize_t bytes) {
	if (buf == NULL || bytes < 4) return false;

	if (strncasecmp(buf, "EHLO", 4) == 0) {
		const ssize_t lenHelo = 4 + lenDomain + AEM_EHLO_RESPONSE_LEN;
		char helo[lenHelo];
		memcpy(helo, "250-", 4);
		memcpy(helo + 4, domain, lenDomain);
		memcpy(helo + 4 + lenDomain, AEM_EHLO_RESPONSE, AEM_EHLO_RESPONSE_LEN);
		return (send(sock, helo, lenHelo, 0) == lenHelo);
	} else if (strncasecmp(buf, "HELO", 4) == 0) {
		const ssize_t lenHelo = 6 + lenDomain;
		char helo[lenHelo];
		memcpy(helo, "250 ", 4);
		memcpy(helo + 4, domain, lenDomain);
		memcpy(helo + 4 + lenDomain, "\r\n", 2);
		return (send(sock, helo, lenHelo, 0) == lenHelo);
	}

	return false;
}

static void tlsClose(mbedtls_ssl_context * const tls) {
	if (tls == NULL) return;
	mbedtls_ssl_close_notify(tls);
	mbedtls_ssl_session_reset(tls);
}

static void smtp_fail(mbedtls_ssl_context *tls, const struct sockaddr_in * const clientAddr, const int code) {
	tlsClose(tls);
	syslog((code < 10 ? LOG_DEBUG : LOG_NOTICE), "Error receiving message (Code: %d, IP: %s)", code, inet_ntoa(clientAddr->sin_addr));
}

void tlsFree(void) {
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}

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

int tlsSetup(mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey) {
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_config_defaults failed: %d", ret); return -1;}

	mbedtls_ssl_conf_arc4_support(&conf, MBEDTLS_SSL_ARC4_ENABLED);
	mbedtls_ssl_conf_ciphersuites(&conf, smtp_ciphersuites);
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1); // Require TLS v1.0+
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ctr_drbg_seed failed: %d", ret); return -1;}

	ret = mbedtls_ssl_conf_own_cert(&conf, tlsCert, tlsKey);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_conf_own_cert failed: %d", ret); return -1;}

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_setup failed: %d", ret); return -1;}

	return 0;
}

void respond_smtp(int sock, const struct sockaddr_in * const clientAddr) {
	if (sock < 0 || domain == NULL || lenDomain < 1 || clientAddr == NULL) return;

	if (!smtp_greet(sock)) return smtp_fail(NULL, clientAddr, 0);

	char buf[AEM_SMTP_SIZE_CMD];
	ssize_t bytes = recv(sock, buf, AEM_SMTP_SIZE_CMD, 0);
	if (bytes < 7) return smtp_fail(NULL, clientAddr, 1); // HELO \r\n

	if (!smtp_helo(sock, buf, bytes)) return smtp_fail(NULL, clientAddr, 2);

	uint8_t infoByte = 0;
	if (buf[0] == 'E') infoByte |= AEM_INFOBYTE_ESMTP;
	const size_t lenGreeting = bytes - 7;
	char greeting[lenGreeting];
	memcpy(greeting, buf + 5, lenGreeting);

	bytes = recv(sock, buf, AEM_SMTP_SIZE_CMD, 0);

	mbedtls_ssl_context *tls = NULL;

	if (bytes >= 8 && strncasecmp(buf, "STARTTLS", 8) == 0) {
		if (!smtp_respond(sock, NULL, '2', '2', '0')) return smtp_fail(tls, clientAddr, 110);

		tls = &ssl;
		mbedtls_ssl_set_bio(tls, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

		int ret;
		while ((ret = mbedtls_ssl_handshake(tls)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				syslog(LOG_NOTICE, "Terminating: mbedtls_ssl_handshake failed: %d", ret);
				tlsClose(tls);
				return;
			}
		}

		bytes = recv_aem(0, tls, buf, AEM_SMTP_SIZE_CMD);
		if (bytes == 0) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			tlsClose(tls);
			return;
		} else if (bytes >= 4 && strncasecmp(buf, "QUIT", 4) == 0) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection cleanly after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			smtp_respond(sock, tls, '2', '2', '1');
			tlsClose(tls);
			return;
		} else if (bytes < 4 || (strncasecmp(buf, "EHLO", 4) != 0 && strncasecmp(buf, "HELO", 4) != 0)) {
			syslog(LOG_DEBUG, "Terminating: Expected EHLO/HELO after StartTLS, but received: %.*s", (int)bytes, buf);
			tlsClose(tls);
			return;
		}

		if (!smtp_shlo(tls)) {
			syslog(LOG_NOTICE, "Terminating: Failed to send greeting following StartTLS");
			tlsClose(tls);
			return;
		}

		bytes = recv_aem(0, tls, buf, AEM_SMTP_SIZE_CMD);
	}

	size_t lenFrom = 0, lenTo = 0;
	char from[AEM_SMTP_MAX_ADDRSIZE];
	char to[AEM_SMTP_MAX_ADDRSIZE_TO];

	char *body = NULL;
	size_t lenBody = 0;

	while(1) {
		if (bytes < 4) {
			if (bytes < 1) syslog(LOG_DEBUG, "Terminating: Client closed connection (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			else syslog(LOG_NOTICE, "Terminating: Invalid data received (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			break;
		}

		if (bytes > 10 && strncasecmp(buf, "MAIL FROM:", 10) == 0) {
			lenFrom = smtp_addr_sender(buf + 10, bytes - 10, from);
			if (lenFrom < 1) {
				return smtp_fail(tls, clientAddr, 100);
			}
		}

		else if (bytes > 8 && strncasecmp(buf, "RCPT TO:", 8) == 0) {
			if (lenFrom < 1) {
				infoByte |= AEM_INFOBYTE_PROTOERR;

				if (!smtp_respond(sock, tls, '5', '0', '3')) {
					tlsClose(tls);
					return smtp_fail(tls, clientAddr, 101);
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
				continue;
			}

			char newTo[AEM_MAXLEN_ADDR32];
			const int lenNewTo = smtp_addr_our(buf + 8, bytes - 8, newTo);

			if (lenNewTo < 1) {
				if (!smtp_respond(sock, tls, '5', '5', '0')) {
					return smtp_fail(tls, clientAddr, 103);
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
				continue;
			}

			if ((lenTo + 1 + lenNewTo) > AEM_SMTP_MAX_ADDRSIZE_TO) {
				if (!smtp_respond(sock, tls, '4', '5', '2')) { // Too many recipients
					return smtp_fail(tls, clientAddr, 104);
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
				continue;
			}

			if (lenTo > 0) {
				to[lenTo] = '\n';
				lenTo++;
			}

			memcpy(to + lenTo, newTo, lenNewTo);
			lenTo += lenNewTo;
		}

		else if (strncasecmp(buf, "RSET", 4) == 0) {
			infoByte |= AEM_INFOBYTE_CMD_RARE;

			lenFrom = 0;
			lenTo = 0;
		}

		else if (strncasecmp(buf, "VRFY", 4) == 0) {
			infoByte |= AEM_INFOBYTE_CMD_RARE;

			if (!smtp_respond(sock, tls, '2', '5', '2')) { // 252 = Cannot VRFY user, but will accept message and attempt delivery
				return smtp_fail(tls, clientAddr, 105);
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
			continue;
		}

		else if (strncasecmp(buf, "QUIT", 4) == 0) {
			smtp_respond(sock, tls, '2', '2', '1');
			break;
		}

		else if (strncasecmp(buf, "DATA", 4) == 0) {
			if (lenFrom < 1 || lenTo < 1) {
				infoByte |= AEM_INFOBYTE_PROTOERR;

				if (!smtp_respond(sock, tls, '5', '0', '3')) {
					return smtp_fail(tls, clientAddr, 106);
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
				continue;
			}

			if (!smtp_respond(sock, tls, '3', '5', '4')) {
				return smtp_fail(tls, clientAddr, 107);
			}

			body = malloc(AEM_SMTP_SIZE_BODY + lenGreeting + lenFrom + 3);
			if (body == NULL) {
				smtp_respond(sock, tls, '4', '2', '1');
				syslog(LOG_ERR, "Failed allocation");
				return smtp_fail(tls, clientAddr, 999);
			}

			// Copy greeting and from address to body
			memcpy(body, greeting, lenGreeting);
			body[lenGreeting] = '\n';
			memcpy(body + lenGreeting + 1, from, lenFrom);
			body[lenGreeting + 1 + lenFrom] = '\n';
			lenBody += lenGreeting + lenFrom + 2;

			// Receive body
			while(1) {
				bytes = recv_aem(sock, tls, body + lenBody, AEM_SMTP_SIZE_BODY - lenBody);
				if (bytes < 1) break;

				lenBody += bytes;

				if (lenBody >= AEM_SMTP_SIZE_BODY) {bytes = 0; break;}
				if (lenBody >= 5 && memcmp(body + lenBody - 5, "\r\n.\r\n", 5) == 0) break;
			}

			if (!smtp_respond(sock, tls, '2', '5', '0')) {
				sodium_memzero(body, lenBody);
				free(body);
				return smtp_fail(tls, clientAddr, 150);
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
			if (bytes >= 4 && strncasecmp(buf, "QUIT", 4) == 0) infoByte |= AEM_INFOBYTE_CMD_QUIT;

			tabsToSpaces(body, lenBody);
			removeControlChars((unsigned char*)body, &lenBody);
			unfoldHeaders(body, &lenBody);
			decodeEncodedWord(body, &lenBody);
			decodeMessage(&body, &lenBody);
			trimSpace(body, &lenBody);
			removeSpaceEnd(body, &lenBody);
			trimLinebreaks(body, &lenBody);
			removeSpaceBegin(body, &lenBody);
			brotliCompress((unsigned char**)&body, &lenBody);

			const int cs = (tls == NULL) ? 0 : mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(tls));
			const uint8_t tlsVersion = getTlsVersion(tls);
			deliverMessage(to, lenTo, from, lenFrom, (unsigned char*)body, lenBody, clientAddr, cs, tlsVersion, infoByte);

			sodium_memzero(from, lenFrom);
			sodium_memzero(to, lenTo);
			sodium_memzero(body, lenBody);

			lenFrom = 0;
			lenTo = 0;
			lenBody = 0;
			free(body);

			if (bytes < 1) break;
			continue;
		}

		else if (strncasecmp(buf, "NOOP", 4) == 0) {
			infoByte |= AEM_INFOBYTE_CMD_RARE;
		}

		else {
			infoByte |= AEM_INFOBYTE_CMD_FAIL;

			// Unsupported commands
			if (!smtp_respond(sock, tls, '5', '0', '0')) {
				return smtp_fail(tls, clientAddr, 108);
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
			continue;
		}

		if (!smtp_respond(sock, tls, '2', '5', '0')) {
			return smtp_fail(tls, clientAddr, 150);
		}

		bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
	}

	tlsClose(tls);
}
