#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <mbedtls/pk.h>
#include <sodium.h>

#include "../Global.h"
#include "../Common/Addr32.h"
#include "../Common/Email.h"
#include "../Common/memeq.h"
#include "../IntCom/Client.h"
#include "../IntCom/Stream_Client.h"

#include "cert.h"

#include "respond.h"

#define AEM_SMTP_MAX_SIZE_CMD 512 // RFC5321: min. 512
#define AEM_SMTP_MAX_ROUNDS 500

#define AEM_EHLO_RESPONSE_LEN 60
#define AEM_EHLO_RESPONSE \
"\r\n250-SIZE 4194304" \
"\r\n250-STARTTLS" \
"\r\n250-8BITMIME" \
"\r\n250 SMTPUTF8"

#define AEM_SHLO_RESPONSE_LEN 46
#define AEM_SHLO_RESPONSE \
"\r\n250-SIZE 4194304" \
"\r\n250-8BITMIME" \
"\r\n250 SMTPUTF8"

static struct emailInfo email;

#include "../Common/tls_setup.c"

__attribute__((warn_unused_result))
static int recv_aem(const int sock, mbedtls_ssl_context * const tls, unsigned char * const buf, const size_t maxSize) {
	if (buf == NULL || maxSize < 1) return -1;

	if (tls != NULL) {
		int ret;
		do {ret = mbedtls_ssl_read(tls, (unsigned char*)buf, maxSize);} while (ret == MBEDTLS_ERR_SSL_WANT_READ);
		return ret;
	}

	if (sock > 0) return recv(sock, buf, maxSize, 0);

	return -1;
}

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

__attribute__((warn_unused_result))
static int smtp_addr_sender(const unsigned char * const buf, const size_t len) {
	if (buf == NULL || len < 1) return -1;

	size_t skipBytes = 0;
	while (skipBytes < len && isspace(buf[skipBytes])) skipBytes++;
	if (skipBytes >= len) return -1;

	if (buf[skipBytes] != '<') return -1;
	skipBytes++;

	const int max = len - skipBytes - 1;
	while (email.lenEnvFr < max && buf[skipBytes + email.lenEnvFr] != '>') (email.lenEnvFr)++;

	// Empty addresses are used by notifications such as bounces
	if (email.lenEnvFr < 1) {
		email.envFr[0] = '@';
		email.lenEnvFr = 1;
		return 0;
	}

	if (email.lenEnvFr > 127) email.lenEnvFr = 127;

	memcpy(email.envFr, buf + skipBytes, email.lenEnvFr);
	return 0;
}

#define AEM_SMTP_ERROR_ADDR_OUR_INTERNAL (-1)
#define AEM_SMTP_ERROR_ADDR_OUR_SYNTAX   (-2)
#define AEM_SMTP_ERROR_ADDR_OUR_USER     (-3)
#define AEM_SMTP_ERROR_ADDR_OUR_DOMAIN   (-4)
#define AEM_SMTP_ERROR_ADDR_TLS_NEEDED   (-5)

static int getUid(const char * const addr, const size_t lenAddr, uint16_t * const uid, unsigned char * const addrFlags) {
	unsigned char addr32[10];
	addr32_store(addr32, addr, lenAddr);

	unsigned char *resp = NULL;
	int32_t lenResp = intcom(AEM_INTCOM_SERVER_ACC, 0, addr32, 10, &resp, sizeof(uint16_t) + 1);
	if (lenResp == AEM_INTCOM_RESPONSE_NOTEXIST) return AEM_SMTP_ERROR_ADDR_OUR_USER;
	if (lenResp != sizeof(uint16_t) + 1) return AEM_SMTP_ERROR_ADDR_OUR_INTERNAL;

	*uid = *(uint16_t*)resp;
	*addrFlags = resp[sizeof(uint16_t)];
	free(resp);
	return 0;
}

#define AEM_ADDROUR_MIN (lenOurDomain + 2)
__attribute__((warn_unused_result))
static int smtp_addr_our(const unsigned char *buf, size_t len, char to[64], uint16_t * const toUid, unsigned char * const addrFlags, const bool isSecure) {
	if (buf == NULL || len < AEM_ADDROUR_MIN) return AEM_SMTP_ERROR_ADDR_OUR_INTERNAL;

	for (size_t i = 0; i < len; i++) {
		if (isspace(*buf)) {
			if (len < AEM_ADDROUR_MIN) return AEM_SMTP_ERROR_ADDR_OUR_DOMAIN;
			buf++;
			len--;
			i--;
		}
	}

	if (*buf == '<') {
		buf++;
		len--;
	}
	if (len < AEM_ADDROUR_MIN) return AEM_SMTP_ERROR_ADDR_OUR_DOMAIN;

	while (!isprint(buf[len - 1]) || buf[len - 1] == '>') {
		if (len - 1 < AEM_ADDROUR_MIN) return 12; // AEM_SMTP_ERROR_ADDR_OUR_DOMAIN
		len--;
	}

	if (len < AEM_ADDROUR_MIN || buf[len - lenOurDomain - 1] != '@' || !memeq_anycase(buf + len - lenOurDomain, ourDomain, lenOurDomain)) return AEM_SMTP_ERROR_ADDR_OUR_DOMAIN;
	if (len - lenOurDomain - 1 > 63) return AEM_SMTP_ERROR_ADDR_OUR_USER;

	size_t lenTo = len - lenOurDomain - 1;
	memcpy(to, buf, lenTo);
	to[lenTo] = '\0';

	const int ret = getUid(to, lenTo, toUid, addrFlags);
	if (ret != 0) return ret;

	return (!isSecure && (*addrFlags & AEM_ADDR_FLAG_SECURE) != 0) ? AEM_SMTP_ERROR_ADDR_TLS_NEEDED : 0;
}

__attribute__((warn_unused_result))
static bool smtp_helo(const int sock, const unsigned char * const buf, const ssize_t bytes) {
	if (buf == NULL || bytes < 4) return false;

	char txt[256];

	if (memeq_anycase(buf, "HELO", 4)) {
		sprintf(txt, "250 %.*s\r\n", lenOurDomain, ourDomain);
		return send_aem(sock, NULL, txt, 6 + lenOurDomain);
	} else if (memeq_anycase(buf, "EHLO", 4)) {
		sprintf(txt, "250-%.*s%s\r\n", lenOurDomain, ourDomain, AEM_EHLO_RESPONSE);
		return send_aem(sock, NULL, txt, 6 + lenOurDomain + AEM_EHLO_RESPONSE_LEN);
	}

	return false;
}

static void tlsClose(mbedtls_ssl_context * const tls) {
	if (tls == NULL) return;
	mbedtls_ssl_close_notify(tls);
	mbedtls_ssl_session_reset(tls);
}

static void smtp_fail(const int code) {
	syslog((code < 10 ? LOG_DEBUG : LOG_NOTICE), "Error receiving message (Code: %d, IP: %u.%u.%u.%u)", code, ((uint8_t*)&email.ip)[0], ((uint8_t*)&email.ip)[1], ((uint8_t*)&email.ip)[2], ((uint8_t*)&email.ip)[3]);
}

void respondClient(int sock, const struct sockaddr_in * const clientAddr) {
	if (clientAddr == NULL) return;
	bzero(&email, sizeof(struct emailInfo));
	email.timestamp = (uint32_t)time(NULL);
	email.ip = clientAddr->sin_addr.s_addr;

	char txt[256];
	sprintf(txt, "220 %.*s\r\n", lenOurDomain, ourDomain);
	if (!send_aem(sock, NULL, txt, 6 + lenOurDomain)) return smtp_fail(0);

	unsigned char buf[AEM_SMTP_MAX_SIZE_CMD];
	ssize_t bytes = recv(sock, buf, AEM_SMTP_MAX_SIZE_CMD, 0);
	if (bytes < 7) return smtp_fail(1); // HELO \r\n

	if (!smtp_helo(sock, buf, bytes)) return smtp_fail(2);

	if (buf[0] == 'E') email.protocolEsmtp = true;

	email.lenGreet = bytes - 7;
	if (email.lenGreet > 63) email.lenGreet = 63;
	memcpy(email.greet, buf + 5, email.lenGreet);

	bytes = recv(sock, buf, AEM_SMTP_MAX_SIZE_CMD, MSG_PEEK);

	mbedtls_ssl_context *tls = NULL;

	if (bytes >= 8 && memeq_anycase(buf, "STARTTLS", 8)) {
		recv(sock, buf, AEM_SMTP_MAX_SIZE_CMD, 0); // Remove the MSG_PEEK'd message from the queue
		if (!send_aem(sock, NULL, "220 Ok\r\n", 8)) return smtp_fail(110);

		tls = &ssl;
		mbedtls_ssl_set_bio(tls, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

		int ret;
		while ((ret = mbedtls_ssl_handshake(tls)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				syslog(LOG_NOTICE, "Terminating: mbedtls_ssl_handshake failed: %x", -ret);
				tlsClose(tls);
				send_aem(sock, NULL, "421 4.7.0 TLS handshake failed\r\n", 32);
				return;
			}
		}

		bytes = recv_aem(0, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
		if (bytes == 0) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreet, email.greet);
			tlsClose(tls);
			return;
		} else if (bytes >= 4 && memeq_anycase(buf, "QUIT", 4)) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection cleanly after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreet, email.greet);
			send_aem(sock, tls, "221 Bye\r\n", 9);
			tlsClose(tls);
			return;
		} else if (bytes < 4 || (!memeq_anycase(buf, "EHLO", 4) && !memeq_anycase(buf, "HELO", 4))) {
			syslog(LOG_DEBUG, "Terminating: Expected EHLO/HELO after StartTLS, but received: %.*s", (int)bytes, buf);
			send_aem(sock, tls, "421 5.5.1 EHLO/HELO required after STARTTLS\r\n", 45);
			tlsClose(tls);
			return;
		}

		sprintf(txt, "250-%.*s%s\r\n", lenOurDomain, ourDomain, AEM_SHLO_RESPONSE);
		if (!send_aem(0, tls, txt, 6 + lenOurDomain + AEM_SHLO_RESPONSE_LEN)) {
			syslog(LOG_NOTICE, "Terminating: Failed sending greeting following StartTLS");
			tlsClose(tls);
			return;
		}

		const mbedtls_x509_crt *clientCert = mbedtls_ssl_get_peer_cert(tls);
		email.tlsInfo =
			getTlsVersion(tls)
		|	cert_getTlsInfo_type(clientCert)
		|	cert_getTlsInfo_name(clientCert, email.greet, email.lenGreet, email.envFr, email.lenEnvFr, email.hdrFr, email.lenHdrFr);

		email.tls_ciphersuite = mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(tls));
	}

	struct emailMeta meta;
	meta.toCount = 0;

	bool deliveryOk = false;

	for (int roundsDone = 0;; roundsDone++) {
		bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);

		if (bytes < 4) {
			if (bytes < 1) syslog(LOG_DEBUG, "Terminating: Client closed connection (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreet, email.greet);
			else syslog(LOG_NOTICE, "Terminating: Invalid data received (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreet, email.greet);
			break;
		} else if (roundsDone > AEM_SMTP_MAX_ROUNDS) {
			send_aem(sock, tls, "421 4.7.0 Too many requests\r\n", 29);
			smtp_fail(200);
			break;
		} else if (bytes > 10 && memeq_anycase(buf, "MAIL FROM:", 10)) {
			if (smtp_addr_sender(buf + 10, bytes - 10) != 0) {smtp_fail(100); break;}
			if (!send_aem(sock, tls, "250 2.1.0 Sender address ok\r\n", 29)) {smtp_fail(101); break;}
		} else if (bytes > 8 && memeq_anycase(buf, "RCPT TO:", 8)) {
			if (email.lenEnvFr < 1) {
				email.protocolViolation = true;
				if (!send_aem(sock, tls, "503 5.5.1 Need sender address first\r\n", 37)) {smtp_fail(102); break;}
				continue;
			}

			if (meta.toCount >= AEM_SMTP_MAX_TO - 1) {
				if (!send_aem(sock, tls, "451 5.5.3 Too many recipients\r\n", 31)) {smtp_fail(103); break;}
				continue;
			}

			bool retOk;
			const bool tlsIsSecure = (tls != NULL && getTlsVersion(tls) >= 2 && (
				   email.tls_ciphersuite == MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
				|| email.tls_ciphersuite == MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
				|| email.tls_ciphersuite == MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
				|| email.tls_ciphersuite == MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
				|| email.tls_ciphersuite == MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
				|| email.tls_ciphersuite == MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			));

			switch (smtp_addr_our(buf + 8, bytes - 8, meta.to[meta.toCount], meta.toUid + meta.toCount, &meta.toFlags[meta.toCount], tlsIsSecure)) {
				case 0:
					retOk = send_aem(sock, tls, "250 2.1.5 Recipient address ok\r\n", 32);
					meta.toCount++;
					break;
				case AEM_SMTP_ERROR_ADDR_OUR_USER:   retOk = send_aem(sock, tls, "550 5.1.1 No such user\r\n", 24); break;
				case AEM_SMTP_ERROR_ADDR_OUR_DOMAIN: retOk = send_aem(sock, tls, "550 5.1.2 Not our domain\r\n", 26); break;
				case AEM_SMTP_ERROR_ADDR_OUR_SYNTAX: retOk = send_aem(sock, tls, "501 5.1.3 Invalid address\r\n", 27); break;
				case AEM_SMTP_ERROR_ADDR_TLS_NEEDED: retOk = send_aem(sock, tls, "450 4.7.0 Recipient requires a secure connection (TLS 1.2)\r\n", 60); meta.toCount++; break; // Record delivery attempt
				default: retOk = send_aem(sock, tls, "451 4.3.0 Internal server error\r\n", 33);
			}
			if (!retOk) {smtp_fail(104); break;}
		} else if (memeq_anycase(buf, "RSET", 4)) {
//			if (!deliveryOk && meta.toCount > 0) deliverMessage(&meta, &email, NULL, 0, false);
			email.rareCommands = true;
			email.lenEnvFr = 0;
			sodium_memzero(&meta, sizeof(struct emailMeta));

			if (!send_aem(sock, tls, "250 Reset\r\n", 11)) {smtp_fail(150); break;}
		} else if (memeq_anycase(buf, "VRFY", 4)) {
			email.rareCommands = true;
			if (!send_aem(sock, tls, "252 Not verified\r\n", 18)) {smtp_fail(105); break;}
		} else if (memeq_anycase(buf, "QUIT", 4)) {
			send_aem(sock, tls, "221 Bye\r\n", 9);
			break;
		} else if (memeq_anycase(buf, "DATA", 4)) {
			if (email.lenEnvFr < 1 || meta.toCount < 1) {
				email.protocolViolation = true;

				bool retOk;
				if (email.lenEnvFr < 1 && meta.toCount < 1) {retOk = send_aem(sock, tls, "503 5.5.1 Need recipient and sender addresses first\r\n", 53);}
				else if (email.lenEnvFr < 1)                {retOk = send_aem(sock, tls, "503 5.5.1 Need sender address first\r\n", 37);}
				else                                        {retOk = send_aem(sock, tls, "503 5.5.1 Need recipient address first\r\n", 40);}
				if (!retOk) {smtp_fail(106); break;}

				continue;
			}

			// Setup IntCom SecretStream to Deliver
			if (intcom_stream_open() != 0) {
				if (!send_aem(sock, tls, "451 4.3.0 Internal server error\r\n", 33)) {smtp_fail(107); break;}
				break;
			}

			if (
			   intcom_stream_send((unsigned char*)&meta, sizeof(struct emailMeta)) != 0
			|| intcom_stream_send((unsigned char*)&email, sizeof(struct emailInfo)) != 0
			) {
				intcom_stream_end();
				if (!send_aem(sock, tls, "451 4.3.0 Internal server error\r\n", 33)) {smtp_fail(107); break;}
				break;
			}

			if (!send_aem(sock, tls, "354 Ok\r\n", 8)) {smtp_fail(107); intcom_stream_end(); break;}

			// Receive the email
			unsigned char body[AEM_SMTP_CHUNKSIZE];
			size_t lenBody = 0;

			while (lenBody < AEM_SMTP_MAX_SIZE_BODY) {
				bytes = recv_aem(sock, tls, body, AEM_SMTP_CHUNKSIZE);
				if (bytes < 1) break;
				if (lenBody + bytes > AEM_SMTP_MAX_SIZE_BODY) bytes = AEM_SMTP_MAX_SIZE_BODY - lenBody;

				const unsigned char * const end = (bytes < 5) ? NULL : memmem(body, bytes, "\r\n.\r\n", 5);
				if (end != NULL) {
					bytes = end - body;
					if (bytes == 0) break;

					lenBody = AEM_SMTP_MAX_SIZE_BODY; // Don't loop any more
				} else lenBody += bytes;

				intcom_stream_send(body, bytes);// TODO check if fail
			}

			sodium_memzero(body, AEM_SMTP_CHUNKSIZE);
			sodium_memzero(&meta, sizeof(struct emailMeta));
			sodium_memzero(&email, sizeof(struct emailInfo));
			email.ip = clientAddr->sin_addr.s_addr;
			deliveryOk = true;

			bool retOk;
			switch (intcom_stream_end()) {
				case AEM_INTCOM_RESPONSE_OK:    retOk = send_aem(sock, tls, "250 Message delivered\r\n", 23); break;
				case AEM_INTCOM_RESPONSE_USAGE: retOk = send_aem(sock, tls, "554 5.3.4 Message too big\r\n", 27); break;
				case AEM_INTCOM_RESPONSE_LIMIT: retOk = send_aem(sock, tls, "452 4.2.2 Recipient mailbox full\r\n", 34); break;
				default:                        retOk = send_aem(sock, tls, "451 4.3.0 Internal server error\r\n", 33);
			}
			if (!retOk) {smtp_fail(108); break;}
		} else if (memeq_anycase(buf, "NOOP", 4)) {
			email.rareCommands = true;
			if (!send_aem(sock, tls, "250 Ok\r\n", 8)) {smtp_fail(150); break;}
		} else { // Unsupported commands
			email.invalidCommands = true;
			if (!send_aem(sock, tls, "500 5.5.1 Command unsupported\r\n", 31)) {smtp_fail(109); break;}
		}
	}

	tlsClose(tls);
	if (!deliveryOk && meta.toCount > 0) {
		sodium_memzero(&email, sizeof(struct emailInfo));
		sodium_memzero(&meta, sizeof(struct emailMeta));
	}
}
