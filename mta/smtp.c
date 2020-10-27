#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <maxminddb.h>
#include <sodium.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "../Common/Brotli.h"
#include "../Common/QuotedPrintable.h"
#include "../Common/ToUtf8.h"
#include "../Common/Trim.h"

#include "delivery.h"
#include "processing.h"

#include "smtp.h"

#include "../Global.h"

#define AEM_SMTP_MAX_SIZE_CMD 512 // RFC5321: min. 512
#define AEM_SMTP_MAX_SIZE_TO 4096 // RFC5321: must accept 100 recipients at minimum
#define AEM_SMTP_MAX_SIZE_BODY 1048576 // 1 MiB. RFC5321: min. 64k; XXX if changed, set the HLO responses and their lengths below also

#define AEM_EHLO_RESPONSE_LEN 60
#define AEM_EHLO_RESPONSE \
"\r\n250-SIZE 1048576" \
"\r\n250-STARTTLS" \
"\r\n250-8BITMIME" \
"\r\n250 SMTPUTF8"

#define AEM_SHLO_RESPONSE_LEN 46
#define AEM_SHLO_RESPONSE \
"\r\n250-SIZE 1048576" \
"\r\n250-8BITMIME" \
"\r\n250 SMTPUTF8"

static struct emailInfo email;

#include "../Common/tls_setup.c"

void setSignKey_mta(const unsigned char * const seed) {
	return setSignKey(seed);
}

static void getCountryCode(const struct sockaddr * const sockAddr) {
	bzero(email.countryCode, 2);
	if (sockAddr == NULL) return;

	MMDB_s mmdb;
	int status = MMDB_open("GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb);
	if (status != MMDB_SUCCESS) {
		syslog(LOG_ERR, "getCountryCode: Can't open database: %s", MMDB_strerror(status));
		return;
	}

	MMDB_lookup_result_s mmdb_result = MMDB_lookup_sockaddr(&mmdb, sockAddr, &status);
	if (status != MMDB_SUCCESS) {
		syslog(LOG_ERR, "getCountryCode: libmaxminddb error: %s", MMDB_strerror(status));
		MMDB_close(&mmdb);
		return;
	}

	if (mmdb_result.found_entry) {
		MMDB_entry_data_s entry_data;
		status = MMDB_get_value(&mmdb_result.entry, &entry_data, "country", "iso_code", NULL);

		if (status == MMDB_SUCCESS) {
			memcpy(email.countryCode, entry_data.utf8_string, 2);
		} else {
			syslog(LOG_ERR, "getCountryCode: Error looking up the entry data: %s", MMDB_strerror(status));
		}
	} else syslog(LOG_ERR, "getCountryCode: No entry for the IP address was found");

	MMDB_close(&mmdb);
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
	return send_aem(sock, tls, (const char[]){code1, code2, code3, ' ', 'a', 'e', 'm', '\r', '\n'}, 9);
}

__attribute__((warn_unused_result))
static int smtp_addr_sender(const char * const buf, const size_t len) {
	if (buf == NULL || len < 1) return -1;

	size_t skipBytes = 0;
	while (skipBytes < len && isspace(buf[skipBytes])) skipBytes++;
	if (skipBytes >= len) return -1;

	if (buf[skipBytes] != '<') return -1;
	skipBytes++;

	const int max = len - skipBytes - 1;
	while (email.lenEnvFrom < max && buf[skipBytes + email.lenEnvFrom] != '>') (email.lenEnvFrom)++;

	// Empty addresses are used by notifications such as bounces
	if (email.lenEnvFrom < 1) {
		email.envFrom[0] = '@';
		email.lenEnvFrom = 1;
		return 0;
	}

	if (email.lenEnvFrom > 127) email.lenEnvFrom = 127;

	memcpy(email.envFrom, buf + skipBytes, email.lenEnvFrom);
	return 0;
}

__attribute__((warn_unused_result))
static size_t smtp_addr_our(const char * const buf, const size_t len, char * const addr) {
	if (buf == NULL || len < 1 || addr == NULL) return 0;

	size_t skipBytes = 0;
	while (skipBytes < len && isspace(buf[skipBytes])) skipBytes++;
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
			if (lenAddr - i - 1 != AEM_DOMAIN_LEN || strncasecmp(buf + skipBytes + i + 1, AEM_DOMAIN, AEM_DOMAIN_LEN) != 0) return 0;
			break;
		}
	}

	return addrChars;
}

__attribute__((warn_unused_result))
static bool smtp_helo(const int sock, const char * const buf, const ssize_t bytes) {
	if (buf == NULL || bytes < 4) return false;

	if (strncasecmp(buf, "HELO", 4) == 0) {
		return send_aem(sock, NULL, "250 "AEM_DOMAIN"\r\n", 6 + AEM_DOMAIN_LEN);
	} else if (strncasecmp(buf, "EHLO", 4) == 0) {
		return send_aem(sock, NULL, "250-"AEM_DOMAIN""AEM_EHLO_RESPONSE"\r\n", 6 + AEM_DOMAIN_LEN + AEM_EHLO_RESPONSE_LEN);
	}

	return false;
}

static void tlsClose(mbedtls_ssl_context * const tls) {
	if (tls == NULL) return;
	mbedtls_ssl_close_notify(tls);
	mbedtls_ssl_session_reset(tls);
}

static void smtp_fail(const struct sockaddr_in * const clientAddr, const int code) {
	syslog((code < 10 ? LOG_DEBUG : LOG_NOTICE), "Error receiving message (Code: %d, IP: %s)", code, inet_ntoa(clientAddr->sin_addr));
}

void respondClient(int sock, const struct sockaddr_in * const clientAddr) {
	if (sock < 0 || clientAddr == NULL) return;
	bzero(&email, sizeof(struct emailInfo));
	getCountryCode((struct sockaddr*)clientAddr);
	email.timestamp = (uint32_t)time(NULL);
	email.ip = clientAddr->sin_addr.s_addr;

	if (!send_aem(sock, NULL, "220 "AEM_DOMAIN"\r\n", 6 + AEM_DOMAIN_LEN)) return smtp_fail(clientAddr, 0);

	char buf[AEM_SMTP_MAX_SIZE_CMD];
	ssize_t bytes = recv(sock, buf, AEM_SMTP_MAX_SIZE_CMD, 0);
	if (bytes < 7) return smtp_fail(clientAddr, 1); // HELO \r\n

	if (!smtp_helo(sock, buf, bytes)) return smtp_fail(clientAddr, 2);

	if (buf[0] == 'E') email.protocolEsmtp = true;

	email.lenGreeting = bytes - 7;
	if (email.lenGreeting > 127) email.lenGreeting = 127;
	memcpy(email.greeting, buf + 5, email.lenGreeting);

	bytes = recv(sock, buf, AEM_SMTP_MAX_SIZE_CMD, 0);

	mbedtls_ssl_context *tls = NULL;

	if (bytes >= 8 && strncasecmp(buf, "STARTTLS", 8) == 0) {
		if (!smtp_respond(sock, NULL, '2', '2', '0')) return smtp_fail(clientAddr, 110);

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

		bytes = recv_aem(0, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
		if (bytes == 0) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreeting, email.greeting);
			tlsClose(tls);
			return;
		} else if (bytes >= 4 && strncasecmp(buf, "QUIT", 4) == 0) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection cleanly after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreeting, email.greeting);
			smtp_respond(sock, tls, '2', '2', '1');
			tlsClose(tls);
			return;
		} else if (bytes < 4 || (strncasecmp(buf, "EHLO", 4) != 0 && strncasecmp(buf, "HELO", 4) != 0)) {
			syslog(LOG_DEBUG, "Terminating: Expected EHLO/HELO after StartTLS, but received: %.*s", (int)bytes, buf);
			tlsClose(tls);
			return;
		}

		if (!send_aem(0, tls, "250-"AEM_DOMAIN""AEM_SHLO_RESPONSE"\r\n", 6 + AEM_DOMAIN_LEN + AEM_SHLO_RESPONSE_LEN)) {
			syslog(LOG_NOTICE, "Terminating: Failed sending greeting following StartTLS");
			tlsClose(tls);
			return;
		}

		email.tls_ciphersuite = mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(tls));
		email.tls_version = getTlsVersion(tls);

		bytes = recv_aem(0, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
	}

	size_t lenTo = 0;
	char to[AEM_SMTP_MAX_SIZE_TO];

	char *body = NULL;
	size_t lenBody = 0;

	while(1) {
		if (bytes < 4) {
			if (bytes < 1) syslog(LOG_DEBUG, "Terminating: Client closed connection (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreeting, email.greeting);
			else syslog(LOG_NOTICE, "Terminating: Invalid data received (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreeting, email.greeting);
			break;
		}

		if (bytes > 10 && strncasecmp(buf, "MAIL FROM:", 10) == 0) {
			if (smtp_addr_sender(buf + 10, bytes - 10) != 0) {
				smtp_fail(clientAddr, 100);
				break;
			}
		}

		else if (bytes > 8 && strncasecmp(buf, "RCPT TO:", 8) == 0) {
			if (email.lenEnvFrom < 1) {
				email.protocolViolation = true;

				if (!smtp_respond(sock, tls, '5', '0', '3')) {
					smtp_fail(clientAddr, 101);
					break;
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
				continue;
			}

			char newTo[AEM_MAXLEN_ADDR32];
			const int lenNewTo = smtp_addr_our(buf + 8, bytes - 8, newTo);

			if (lenNewTo < 1) {
				if (!smtp_respond(sock, tls, '5', '5', '0')) {
					smtp_fail(clientAddr, 103);
					break;
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
				continue;
			}

			if ((lenTo + 1 + lenNewTo) > AEM_SMTP_MAX_SIZE_TO) {
				if (!smtp_respond(sock, tls, '4', '5', '2')) { // Too many recipients
					smtp_fail(clientAddr, 104);
					break;
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
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
			email.rareCommands = true;

			email.lenEnvFrom = 0;
			lenTo = 0;
		}

		else if (strncasecmp(buf, "VRFY", 4) == 0) {
			email.rareCommands = true;

			if (!smtp_respond(sock, tls, '2', '5', '2')) { // 252 = Cannot VRFY user, but will accept message and attempt delivery
				smtp_fail(clientAddr, 105);
				break;
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
			continue;
		}

		else if (strncasecmp(buf, "QUIT", 4) == 0) {
			smtp_respond(sock, tls, '2', '2', '1');
			break;
		}

		else if (strncasecmp(buf, "DATA", 4) == 0) {
			if (email.lenEnvFrom < 1 || lenTo < 1) {
				email.protocolViolation = true;

				if (!smtp_respond(sock, tls, '5', '0', '3')) {
					smtp_fail(clientAddr, 106);
					break;
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
				continue;
			}

			if (!smtp_respond(sock, tls, '3', '5', '4')) {
				smtp_fail(clientAddr, 107);
				break;
			}

			body = malloc(email.lenGreeting + email.lenRdns + email.lenCharset + email.lenEnvFrom + AEM_SMTP_MAX_SIZE_BODY);
			if (body == NULL) {
				smtp_respond(sock, tls, '4', '2', '1');
				syslog(LOG_ERR, "Failed allocation");
				smtp_fail(clientAddr, 999);
				break;
			}

			lenBody = 0;
			memcpy(body + lenBody, email.greeting, email.lenGreeting); lenBody += email.lenGreeting;
			memcpy(body + lenBody, email.rdns,     email.lenRdns);     lenBody += email.lenRdns;
			memcpy(body + lenBody, email.charset,  email.lenCharset);  lenBody += email.lenCharset;
			memcpy(body + lenBody, email.envFrom,  email.lenEnvFrom);  lenBody += email.lenEnvFrom;

			// Receive body
			while(1) {
				bytes = recv_aem(sock, tls, body + lenBody, AEM_SMTP_MAX_SIZE_BODY - lenBody);
				if (bytes < 1) break;

				lenBody += bytes;

				if (lenBody >= AEM_SMTP_MAX_SIZE_BODY) {bytes = 0; break;}
				if (lenBody >= 5 && memcmp(body + lenBody - 5, "\r\n.\r\n", 5) == 0) {
					lenBody -= 5;
					break;
				}
			}

			if (!smtp_respond(sock, tls, '2', '5', '0')) {
				sodium_memzero(body, lenBody);
				free(body);
				smtp_fail(clientAddr, 150);
				break;
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
			if (bytes >= 4 && strncasecmp(buf, "QUIT", 4) == 0) email.quitReceived = true;

			convertLineDots(body, &lenBody);

			if (prepareHeaders(body, &lenBody) == 0) {
				unfoldHeaders(body, &lenBody);
				decodeEncodedWord(body, &lenBody);
				decodeMessage(&body, &lenBody, &email);
				convertNbsp(body, &lenBody);
				trimSpace(body, &lenBody);
				removeSpaceEnd(body, &lenBody);
				trimLinebreaks(body, &lenBody);
				removeSpaceBegin(body, &lenBody);
				trimEnd(body, &lenBody);
			}
			brotliCompress((unsigned char**)&body, &lenBody);

			deliverMessage(to, lenTo, (unsigned char*)body, lenBody, &email);

			sodium_memzero(&email, sizeof(struct emailInfo));
			sodium_memzero(to, lenTo);
			sodium_memzero(body, lenBody);

			lenTo = 0;
			lenBody = 0;
			free(body);

			if (bytes < 1) break;
			continue;
		}

		else if (strncasecmp(buf, "NOOP", 4) == 0) {
			email.rareCommands = true;
		}

		else {
			email.invalidCommands = true;

			// Unsupported commands
			if (!smtp_respond(sock, tls, '5', '0', '0')) {
				smtp_fail(clientAddr, 108);
				break;
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
			continue;
		}

		if (!smtp_respond(sock, tls, '2', '5', '0')) {
			smtp_fail(clientAddr, 150);
			break;
		}

		bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
	}

	tlsClose(tls);
}
