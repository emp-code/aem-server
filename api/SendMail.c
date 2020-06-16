#define _GNU_SOURCE // for strcasestr

#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>

#include <sodium.h>

#include "../Global.h"

#include "SendMail.h"

#define AEM_API_SENDMAIL
#define AEM_CLIENT_TIMEOUT 30

static bool useTls;

static char domain[AEM_MAXLEN_DOMAIN];
static size_t lenDomain;

static mbedtls_x509_crt tlsCrt;
static mbedtls_pk_context tlsKey;

static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_x509_crt cacert;

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

__attribute__((warn_unused_result))
static uint8_t getTlsVersion(const mbedtls_ssl_context * const tls) {
	if (tls == NULL) return 0;

	const char * const c = mbedtls_ssl_get_version(tls);
	if (c == NULL || strncmp(c, "TLSv1.", 6) != 0) return 0;

	switch(c[6]) {
		case '0': return 1;
		case '1': return 2;
		case '2': return 3;
		case '3': return 4;
	}

	return 0;
}

void tlsFree_sendmail(void) {
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_x509_crt_free(&cacert);
}

int tlsSetup_sendmail(const unsigned char * const crtData, const size_t crtLen, const unsigned char * const keyData, const size_t keyLen) {
	mbedtls_x509_crt_init(&tlsCrt);
	int ret = mbedtls_x509_crt_parse(&tlsCrt, crtData, crtLen);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_x509_crt_parse failed: %x", -ret); return -1;}

	mbedtls_pk_init(&tlsKey);
	ret = mbedtls_pk_parse_key(&tlsKey, keyData, keyLen, NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_pk_parse_key failed: %x", -ret); return -1;}

	if (getDomainFromCert() != 0) {syslog(LOG_ERR, "Failed getting domain from certificate"); return -1;}

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
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1); // Require TLS v1.0+
	mbedtls_ssl_conf_own_cert(&conf, &tlsCrt, &tlsKey);
	mbedtls_ssl_conf_renegotiation(&conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {syslog(LOG_ERR, "mbedtls_ssl_setup failed: %x", -ret); return -1;}
	return 0;
}

static int makeSocket(const uint32_t ip) {
	const int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {syslog(LOG_ERR, "Failed socket(): %m"); return -1;}

	struct in_addr ipAddr;
	ipAddr.s_addr = ip;

	struct sockaddr_in mxAddr;
	mxAddr.sin_family = AF_INET;
	mxAddr.sin_port = htons(25);
	mxAddr.sin_addr = ipAddr;

	if (connect(sock, (struct sockaddr*)&mxAddr, sizeof(struct sockaddr_in)) != 0) {syslog(LOG_ERR, "Failed connect(): %m"); close(sock); return -1;}

	return sock;
}

static char *createEmail(const unsigned char * const addrFrom, const size_t lenAddrFrom, const unsigned char * const addrTo, const size_t lenAddrTo, const unsigned char * const title, const size_t lenTitle, const unsigned char * const body, const size_t lenBody) {
	char msgId[32];
	randombytes_buf(msgId, 32);

	char *email = sodium_malloc(1000 + lenTitle + lenBody);
	sprintf(email,
		"From: <%.*s>\r\n"
		"To: <%.*s>\r\n"
		"Subject: %.*s\r\n"
		"Date: \r\n"
		"Message-ID: <%32s@%.*s>\r\n"
		"\r\n"
		"%.*s"
		"\r\n"
		"."
		"\r\n"
	, (int)lenAddrFrom, addrFrom
	, (int)lenAddrTo, addrTo
	, (int)lenTitle, title
	, msgId, (int)lenDomain, domain, (int)lenBody, body);

	return email;
}

static int smtp_recv(const int sock, char * const buf, const size_t len) {
	if (!useTls) return recv(sock, buf, len, 0);

	int ret;
	do {ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, len);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
	return ret;
}

static int smtp_send(const int sock, const char * const data, const size_t lenData) {
	if (!useTls) return (send(sock, data, lenData, 0) == (ssize_t)lenData) ? 0 : -1;

	size_t sent = 0;

	while (sent < lenData) {
		int ret;
		do {ret = mbedtls_ssl_write(&ssl, (const unsigned char*)(data + sent), lenData - sent);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
		if (ret < 0) return ret;

		sent += ret;
	}

	return sent;
}

static void closeTls(const int sock) {
	if (useTls) {
		mbedtls_ssl_close_notify(&ssl);
		mbedtls_ssl_session_reset(&ssl);
	}

	close(sock);
}

int sendMail(const uint32_t ip, const unsigned char * const addrFrom, const size_t lenAddrFrom, const unsigned char * const addrTo, const size_t lenAddrTo, const unsigned char * const title, const size_t lenTitle, const unsigned char * const body, const size_t lenBody) {
	int sock = makeSocket(ip);
	if (sock < 1) return -1;
	useTls = false;

	char greeting[256];
	const ssize_t lenGreeting = smtp_recv(sock, greeting, 256);
	if (lenGreeting < 4 || memcmp(greeting, "220 ", 4) != 0) {close(sock); return AEM_SENDMAIL_ERR_RECV_GREET;}

	char buf[1024];
	sprintf(buf, "EHLO %.*s\r\n", (int)lenDomain, domain);
	if (smtp_send(sock, buf, strlen(buf)) < 0) {close(sock); return AEM_SENDMAIL_ERR_SEND_EHLO;}

	ssize_t len = smtp_recv(sock, buf, 1024);
	if (len < 4 || memcmp(buf, "250", 3) != 0) {close(sock); return AEM_SENDMAIL_ERR_RECV_EHLO;}

	buf[len] = '\0';
	if (strcasestr(buf, "STARTTLS") != NULL) {
		if (smtp_send(sock, "STARTTLS\r\n", 10) < 0) {close(sock); return AEM_SENDMAIL_ERR_SEND_STARTTLS;}

		len = smtp_recv(sock, buf, 1024);
		if (len < 4 || memcmp(buf, "220", 3) != 0) {close(sock); return AEM_SENDMAIL_ERR_RECV_STARTTLS;}

//		mbedtls_ssl_set_hostname(&ssl, "");
		mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

		int ret;
		while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				syslog(LOG_WARNING, "SendMail: Handshake failed: %x", -ret);
				closeTls(sock);
				return -1;
			}
		}

		useTls = true;

		char buf[1024];
		sprintf(buf, "EHLO %.*s\r\n", (int)lenDomain, domain);
		if (smtp_send(sock, buf, strlen(buf)) < 0) {closeTls(sock); return AEM_SENDMAIL_ERR_SEND_EHLO;}

		len = smtp_recv(sock, buf, 1024);
		if (len < 4 || memcmp(buf, "250", 3) != 0) {closeTls(sock); return AEM_SENDMAIL_ERR_RECV_EHLO;}
	}

	const uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
	if (flags != 0) {syslog(LOG_ERR, "SendMail: Failed verifying cert"); closeTls(sock); return -1;}

	// From
	sprintf(buf, "MAIL FROM: <%.*s@%.*s>\r\n", (int)lenAddrFrom, addrFrom, (int)lenDomain, domain);
	if (smtp_send(sock, buf, strlen(buf)) < 0) {closeTls(sock); return AEM_SENDMAIL_ERR_SEND_MAIL;}
	len = smtp_recv(sock, buf, 128);
	if (len < 4 || memcmp(buf, "250 ", 4) != 0) {closeTls(sock); return AEM_SENDMAIL_ERR_RECV_MAIL;} 

	// To
	sprintf(buf, "RCPT TO: <%.*s>\r\n", (int)lenAddrTo, addrTo);
	if (smtp_send(sock, buf, strlen(buf)) < 0) {closeTls(sock); return AEM_SENDMAIL_ERR_SEND_RCPT;}
	len = smtp_recv(sock, buf, 128);
	if (len < 4 || memcmp(buf, "250 ", 4) != 0) {closeTls(sock); return AEM_SENDMAIL_ERR_RECV_RCPT;} 

	// Data
	if (smtp_send(sock, "DATA", 4) < 0) {closeTls(sock); return AEM_SENDMAIL_ERR_SEND_DATA;}
	len = smtp_recv(sock, buf, 128);
	if (len < 4 || memcmp(buf, "354 ", 4) != 0) {closeTls(sock); return AEM_SENDMAIL_ERR_RECV_DATA;} 

	char *msg = createEmail(addrFrom, lenAddrFrom, addrTo, lenAddrTo, title, lenTitle, body, lenBody);
	if (smtp_send(sock, msg, strlen(msg)) < 0) {sodium_free(msg); closeTls(sock); return AEM_SENDMAIL_ERR_SEND_BODY;}
	sodium_free(msg);

	len = smtp_recv(sock, buf, 128);
	if (len < 4 || memcmp(buf, "250 ", 4) != 0) {closeTls(sock); return AEM_SENDMAIL_ERR_RECV_BODY;} 

	// Quit
	if (smtp_send(sock, "QUIT", 4) < 0) {closeTls(sock); return AEM_SENDMAIL_ERR_SEND_QUIT;}
	len = smtp_recv(sock, buf, 128);
	if (len < 4 || memcmp(buf, "221 ", 4) != 0) {closeTls(sock); return AEM_SENDMAIL_ERR_RECV_QUIT;} 

	closeTls(sock);
	return 0;
}
