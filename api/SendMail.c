#define _GNU_SOURCE // for memmem

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
#include <mbedtls/sha256.h>
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

static unsigned char dkim_adm_skey[AEM_LEN_KEY_DKI];
static unsigned char dkim_usr_skey[AEM_LEN_KEY_DKI];

// EdDSA
//	unsigned char tmp[crypto_sign_SECRETKEYBYTES];
//	crypto_sign_seed_keypair(tmp, dkim_adm_skey, seed);

void setDkimAdm(const unsigned char * const new) {
	memcpy(dkim_adm_skey, new, AEM_LEN_KEY_DKI);
}

void setDkimUsr(const unsigned char * const new) {
	memcpy(dkim_usr_skey, new, AEM_LEN_KEY_DKI);
}

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

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
//	mbedtls_ssl_conf_dhm_min_bitlen(&conf, 2048); // Minimum length for DH parameters
	mbedtls_ssl_conf_fallback(&conf, MBEDTLS_SSL_IS_NOT_FALLBACK);
//	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1); // Require TLS v1.0+
//	mbedtls_ssl_conf_own_cert(&conf, &tlsCrt, &tlsKey);
//	mbedtls_ssl_conf_renegotiation(&conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
//	mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);

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

static int rsa_sign_b64(const unsigned char hash[32], char sigB64[sodium_base64_ENCODED_LEN(256, sodium_base64_VARIANT_ORIGINAL)], const bool isAdmin) {
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	int ret = mbedtls_pk_parse_key(&pk, isAdmin? dkim_adm_skey : dkim_usr_skey, 1 + strlen((char*)(isAdmin? dkim_adm_skey : dkim_usr_skey)), NULL, 0);
	if (ret != 0) {syslog(LOG_ERR, "pk_parse failed: %d", ret); mbedtls_pk_free(&pk); return -1;}

	// Calculate the signature of the hash
	unsigned char sig[256];
	size_t olen;
	ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, sig, &olen, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_pk_free(&pk);
	if (ret != 0) {syslog(LOG_ERR, "pk_sign failed: %d", ret); return -1;}

	sodium_bin2base64(sigB64, sodium_base64_ENCODED_LEN(256, sodium_base64_VARIANT_ORIGINAL), sig, 256, sodium_base64_VARIANT_ORIGINAL);
	return 0;
}

static char *createEmail(const int userLevel, const unsigned char *replyId, const size_t lenReplyId, const unsigned char * const addrFrom, const size_t lenAddrFrom, const unsigned char * const addrTo, const size_t lenAddrTo, const unsigned char * const title, const size_t lenTitle, const unsigned char * const body, const size_t lenBody) {
	unsigned char body2[lenBody + 2000];

	size_t lenBody2 = 0;
	for (size_t copied = 0; copied < lenBody; copied++) {
		if (body[copied] == '\n' && (copied < 1 || body[copied - 1] != '\r')) {
			body2[lenBody2] = '\r';
			lenBody2++;
		}

		body2[lenBody2] = body[copied];
		lenBody2++;
		if (lenBody2 > lenBody + 1950) return NULL;
	}

	body2[lenBody2] = '\r';
	body2[lenBody2 + 1] = '\n';
	lenBody2 += 2;

	unsigned char bodyHash[32];
	if (mbedtls_sha256_ret(body2, lenBody2, bodyHash, 0) != 0) return NULL;

	char bodyHashB64[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL) + 1];
	sodium_bin2base64(bodyHashB64, sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL) + 1, bodyHash, 32, sodium_base64_VARIANT_ORIGINAL);

	unsigned char msgIdBin[24];
	randombytes_buf(msgIdBin, 24);
	char msgId[33];
	sodium_bin2base64(msgId, 33, msgIdBin, 24, sodium_base64_VARIANT_URLSAFE);

	const uint32_t ts = (uint32_t)time(NULL);

	const time_t msgTime = ts - 1 - randombytes_uniform(15);
	struct tm ourTime;
	if (localtime_r(&msgTime, &ourTime) == NULL) return NULL;
	char rfctime[64];
	strftime(rfctime, 64, "%a, %d %b %Y %T %z", &ourTime); // Wed, 17 Jun 2020 08:30:21 +0000

// header-hash = SHA256(headers, crlf separated + DKIM-Signature-field with b= empty, no crlf)
	char *email = sodium_malloc(2000 + lenTitle + lenBody2);
	if (email == NULL) return NULL;
	bzero(email, 2000 + lenTitle + lenBody2);

	char ref[1000];
	if (replyId != NULL && lenReplyId > 5) { // a@b.cd
		sprintf(ref,
			"References: <%.*s>\r\n"
			"In-Reply-To: <%.*s>\r\n"
		, (int)lenReplyId, replyId, (int)lenReplyId, replyId);
	} else ref[0] = '\0';

	sprintf(email,
		"%s" // Reply headers
		"From: %.*s@%.*s\r\n"
		"Date: %s\r\n"
		"Message-ID: <%s@%.*s>\r\n"
		"Subject: %.*s\r\n"
		"To: %.*s\r\n"
		"DKIM-Signature:"
			" v=1;"
			" a=rsa-sha256;" //ed25519-sha256
			" c=simple/simple;"
			" d=%.*s;"
			" i=@%.*s;"
			" q=dns/txt;"
			" s=%s;"
			" t=%u;"
			" x=%u;"
			" h=references:in-reply-to:from:date:message-id:subject:to;"
			" bh=%s;"
			" b="
	, ref
	, (int)lenAddrFrom, addrFrom, (int)lenDomain, domain
	, rfctime
	, msgId, (int)lenDomain, domain
	, (int)lenTitle, title
	, (int)lenAddrTo, addrTo
	, (int)lenDomain, domain //d=
	, (int)lenDomain, domain //i=
	, (userLevel == AEM_USERLEVEL_MAX) ? "admin" : "users"
	, ts // t=
	, ts + 86400 // expire after a day
	, bodyHashB64
	);

	unsigned char headHash[32];
	if (mbedtls_sha256_ret((unsigned char*)email, strlen(email), headHash, 0) != 0) {sodium_free(email); return NULL;}

// RSA
	char sigB64[sodium_base64_ENCODED_LEN(256, sodium_base64_VARIANT_ORIGINAL)];
	if (rsa_sign_b64(headHash, sigB64, (userLevel == AEM_USERLEVEL_MAX)) != 0) {sodium_free(email); return NULL;}

// EdDSA
/*
	unsigned char sig[crypto_sign_BYTES];
	crypto_sign_detached(sig, NULL, headHash, 32, (userLevel == AEM_USERLEVEL_MAX) ? dkim_adm_skey : dkim_usr_skey);

	char sigB64[sodium_base64_ENCODED_LEN(crypto_sign_BYTES, sodium_base64_VARIANT_ORIGINAL)];
	sodium_bin2base64(sigB64, sodium_base64_ENCODED_LEN(crypto_sign_BYTES, sodium_base64_VARIANT_ORIGINAL), sig, crypto_sign_BYTES, sodium_base64_VARIANT_ORIGINAL);
*/

	strcpy(email + strlen(email), sigB64);
	const size_t lenMsg = strlen(email) + 2;
	memcpy(email + strlen(email), "\r\n", 2);
	char *dkim = strstr(email, "\nDKIM-Signature:");
	memmove(email + strlen(email), email, dkim - email); // Move headers after dkim-sig
	memmove(email, dkim + 1, strlen(dkim + 1)); // Move everything back to the beginning

	sprintf(email + lenMsg, "\r\n%.*s\r\n.\r\n", (int)lenBody2, body2);

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

int sendMail(const uint32_t ip, const int userLevel, const unsigned char *replyId, const size_t lenReplyId, const unsigned char * const addrFrom, const size_t lenAddrFrom, const unsigned char * const addrTo, const size_t lenAddrTo, const unsigned char * const title, const size_t lenTitle, const unsigned char * const body, const size_t lenBody) {
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

	if (memmem(buf, len, "STARTTLS", 8) != NULL) {
		if (smtp_send(sock, "STARTTLS\r\n", 10) < 0) {close(sock); return AEM_SENDMAIL_ERR_SEND_STARTTLS;}

		len = smtp_recv(sock, buf, 1024);
		if (len < 4 || memcmp(buf, "220", 3) != 0) {close(sock); return AEM_SENDMAIL_ERR_RECV_STARTTLS;}

//		mbedtls_ssl_set_hostname(&ssl, "");
		mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

		int ret;
		while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				syslog(LOG_WARNING, "SendMail: Handshake failed: %x", ret);
				closeTls(sock);
				return -1;
			}
		}

		const uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
		if (flags != 0) {syslog(LOG_ERR, "SendMail: Failed verifying cert");} //closeTls(sock); return -1;}

		useTls = true;

		sprintf(buf, "EHLO %.*s\r\n", (int)lenDomain, domain);
		if (smtp_send(sock, buf, strlen(buf)) < 0) {closeTls(sock); return AEM_SENDMAIL_ERR_SEND_EHLO;}

		len = smtp_recv(sock, buf, 1024);
		if (len < 4 || memcmp(buf, "250", 3) != 0) {closeTls(sock); return AEM_SENDMAIL_ERR_RECV_EHLO;}
	}

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
	if (smtp_send(sock, "DATA\r\n", 6) < 0) {closeTls(sock); return AEM_SENDMAIL_ERR_SEND_DATA;}
	len = smtp_recv(sock, buf, 128);
	if (len < 4 || memcmp(buf, "354 ", 4) != 0) {closeTls(sock); return AEM_SENDMAIL_ERR_RECV_DATA;} 

	char *msg = createEmail(userLevel, replyId, lenReplyId, addrFrom, lenAddrFrom, addrTo, lenAddrTo, title, lenTitle, body, lenBody);
	if (msg == NULL) {closeTls(sock); return -1;}
	if (smtp_send(sock, msg, strlen(msg)) < 0) {sodium_free(msg); closeTls(sock); return AEM_SENDMAIL_ERR_SEND_BODY;}
	sodium_free(msg);

	len = smtp_recv(sock, buf, 128);
	if (len < 4 || memcmp(buf, "250 ", 4) != 0) {closeTls(sock); return AEM_SENDMAIL_ERR_RECV_BODY;}

	// Quit
	if (smtp_send(sock, "QUIT\r\n", 6) < 0) {closeTls(sock); return AEM_SENDMAIL_ERR_SEND_QUIT;}
	len = smtp_recv(sock, buf, 128);
	closeTls(sock);

	return (len > 3 || memcmp(buf, "221 ", 4) == 0) ? 0 : AEM_SENDMAIL_ERR_RECV_QUIT;
}
