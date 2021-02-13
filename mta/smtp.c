#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <mbedtls/pk.h>
#include <sodium.h>

#include "../Common/Addr32.h"
#include "../Common/QuotedPrintable.h"
#include "../Common/ToUtf8.h"
#include "../Common/Trim.h"
#include "../Common/UnixSocketClient.h"

#include "date.h"
#include "delivery.h"
#include "processing.h"

#include "smtp.h"

#include "../Global.h"

#define AEM_SMTP_MAX_SIZE_CMD 512 // RFC5321: min. 512
#define AEM_SMTP_MAX_TO 128 // RFC5321: must accept 100 recipients at minimum
#define AEM_SMTP_MAX_SIZE_BODY 1048576 // 1 MiB. RFC5321: min. 64k; XXX if changed, set the HLO responses and their lengths below also
#define AEM_SMTP_MAX_ROUNDS 500

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

static uint16_t getCertType(const mbedtls_x509_crt * const cert) {
	if (cert == NULL) return AEM_EMAIL_CERT_NONE;

	const size_t keyBits = mbedtls_pk_get_bitlen(&cert->pk);

	if (strcmp(mbedtls_pk_get_name(&cert->pk), "RSA") == 0) {
		if      (keyBits >= 4096) return AEM_EMAIL_CERT_RSA4K;
		else if (keyBits >= 2048) return AEM_EMAIL_CERT_RSA2K;
		else if (keyBits >= 1024) return AEM_EMAIL_CERT_RSA1K;
	} else if (strcmp(mbedtls_pk_get_name(&cert->pk), "EC") == 0) {
		if      (keyBits >= 521) return AEM_EMAIL_CERT_EC521;
		else if (keyBits >= 384) return AEM_EMAIL_CERT_EC384;
		else if (keyBits >= 256) return AEM_EMAIL_CERT_EC256;
	} else if (strcmp(mbedtls_pk_get_name(&cert->pk), "EDDSA") == 0) return AEM_EMAIL_CERT_EDDSA;

	return AEM_EMAIL_CERT_NONE;
}

static void getCertNames(const mbedtls_x509_crt * const cert) {
	if (cert == NULL) return;

	bool firstDone = false;
	const mbedtls_asn1_sequence *s = &cert->subject_alt_names;

	while(1) {
		size_t lenName;
		const unsigned char *name;

		if (!firstDone) {
			lenName = cert->subject.val.len;
			name = cert->subject.val.p;
			firstDone = true;
		} else {
			if (s == NULL) break;
			lenName = s->buf.len;
			name = s->buf.p;
			s = s->next;
		}

		if (name != NULL && lenName > 0) {
			// TODO: Support wildcards: *.example.com
			if (lenName == email.lenGreeting && memcmp(name, email.greeting, lenName) == 0) email.tlsInfo |= AEM_EMAIL_CERT_MATCH_GREETING;
			if (lenName == email.lenRdns     && memcmp(name, email.rdns,     lenName) == 0) email.tlsInfo |= AEM_EMAIL_CERT_MATCH_RDNS;

			const unsigned char *envFrom = memchr(email.envFrom, '@', email.lenEnvFrom);
			if (envFrom != NULL) {
				envFrom++;
				const size_t lenEnvFrom = email.lenEnvFrom - (envFrom - email.envFrom);
				if (lenName == lenEnvFrom && memcmp(name, envFrom, lenName) == 0) email.tlsInfo |= AEM_EMAIL_CERT_MATCH_ENVFROM;
			}

			const unsigned char *hdrFrom = memchr(email.headerFrom, '@', email.lenHeaderFrom);
			if (hdrFrom != NULL) {
				hdrFrom++;
				const size_t lenHdrFrom = email.lenHeaderFrom - (hdrFrom - email.headerFrom);
				if (lenName == lenHdrFrom && memcmp(name, hdrFrom, lenName) == 0) email.tlsInfo |= AEM_EMAIL_CERT_MATCH_HEADERFROM;
			}
		}
	}
}

static void getIpInfo(void) {
	email.lenRdns = 0;
	email.ccBytes[0] |= 31;
	email.ccBytes[1] |= 31;

	const int sock = enquirySocket(AEM_ENQUIRY_IP, (unsigned char*)&email.ip, 4);
	if (sock >= 0) {
		unsigned char ipInfo[129];
		const int lenIpInfo = recv(sock, ipInfo, 129, 0);

		if (lenIpInfo >= 2) {
			memcpy(email.ccBytes, ipInfo, 2);

			if (lenIpInfo > 2) {
				email.lenRdns = lenIpInfo - 2;
				memcpy(email.rdns, ipInfo + 2, email.lenRdns);
			}
		}

		close(sock);
	} else syslog(LOG_ERR, "Failed connecting to Enquiry");
}

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
static int smtp_addr_sender(const unsigned char * const buf, const size_t len) {
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
static int smtp_addr_our(const unsigned char * const buf, const size_t len, char to[32]) {
	if (buf == NULL || len < 1) return -1;

	size_t skipBytes = 0;
	while (skipBytes < len && isspace(buf[skipBytes])) skipBytes++;
	if (skipBytes >= len) return -1;

	if (buf[skipBytes] != '<') return -1;
	skipBytes++;

	const int max = len - skipBytes - 1;
	int lenAddr = 0;
	while (lenAddr < max && buf[skipBytes + lenAddr] != '>') lenAddr++;

	if (lenAddr < 1) return -1;

	char addr[AEM_MAXLEN_ADDR32];
	int addrChars = 0;
	int toChars = 0;
	for (int i = 0; i < lenAddr; i++) {
		if (buf[skipBytes + i] == '@') {
			if (lenAddr - i - 1 != AEM_DOMAIN_LEN || strncasecmp((char*)buf + skipBytes + i + 1, AEM_DOMAIN, AEM_DOMAIN_LEN) != 0) return -1;
			break;
		}

		if (toChars >= 31) return -1;
		to[toChars] = buf[skipBytes + i];
		toChars++;

		if (isalnum(buf[skipBytes + i])) {
			if (addrChars + 1 > AEM_MAXLEN_ADDR32) return -1;
			addr[addrChars] = tolower(buf[skipBytes + i]);
			addrChars++;
		}
	}

	if (
	   (addrChars == 6 && memcmp(addr, "system", 6) == 0)
	|| (addrChars == 6 && memcmp(addr, "public", 6) == 0)
	|| (addrChars == 16 && memcmp(addr + 3, "administrator", 13) == 0)
	) return -1;

	if (addrChars == 16) { // Shield addresses: check if exists
		unsigned char addr32[10];
		addr32_store(addr32, addr, addrChars);

		const int sock = accountSocket(AEM_MTA_ADREXISTS_SHIELD, addr32, 10);
		if (sock >= 0) {
			unsigned char tmp;
			const ssize_t ret = recv(sock, &tmp, 1, 0);
			close(sock);
			if (ret != 1) return -1;
		}
	}

	to[toChars] = '\0';

	return 0;
}

__attribute__((warn_unused_result))
static bool smtp_helo(const int sock, const unsigned char * const buf, const ssize_t bytes) {
	if (buf == NULL || bytes < 4) return false;

	if (strncasecmp((char*)buf, "HELO", 4) == 0) {
		return send_aem(sock, NULL, "250 "AEM_DOMAIN"\r\n", 6 + AEM_DOMAIN_LEN);
	} else if (strncasecmp((char*)buf, "EHLO", 4) == 0) {
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
	email.timestamp = (uint32_t)time(NULL);
	email.ip = clientAddr->sin_addr.s_addr;

	if (!send_aem(sock, NULL, "220 "AEM_DOMAIN"\r\n", 6 + AEM_DOMAIN_LEN)) return smtp_fail(clientAddr, 0);

	unsigned char buf[AEM_SMTP_MAX_SIZE_CMD];
	ssize_t bytes = recv(sock, buf, AEM_SMTP_MAX_SIZE_CMD, 0);
	if (bytes < 7) return smtp_fail(clientAddr, 1); // HELO \r\n

	if (!smtp_helo(sock, buf, bytes)) return smtp_fail(clientAddr, 2);

	if (buf[0] == 'E') email.protocolEsmtp = true;

	email.lenGreeting = bytes - 7;
	if (email.lenGreeting > 127) email.lenGreeting = 127;
	memcpy(email.greeting, buf + 5, email.lenGreeting);

	bytes = recv(sock, buf, AEM_SMTP_MAX_SIZE_CMD, 0);

	mbedtls_ssl_context *tls = NULL;
	const mbedtls_x509_crt *clientCert = NULL;

	if (bytes >= 8 && strncasecmp((char*)buf, "STARTTLS", 8) == 0) {
		if (!smtp_respond(sock, NULL, '2', '2', '0')) return smtp_fail(clientAddr, 110);

		tls = &ssl;
		mbedtls_ssl_set_bio(tls, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

		int ret;
		while ((ret = mbedtls_ssl_handshake(tls)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				syslog(LOG_NOTICE, "Terminating: mbedtls_ssl_handshake failed: %x", -ret);
				tlsClose(tls);
				return;
			}
		}

		bytes = recv_aem(0, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
		if (bytes == 0) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreeting, email.greeting);
			tlsClose(tls);
			return;
		} else if (bytes >= 4 && strncasecmp((char*)buf, "QUIT", 4) == 0) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection cleanly after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreeting, email.greeting);
			smtp_respond(sock, tls, '2', '2', '1');
			tlsClose(tls);
			return;
		} else if (bytes < 4 || (strncasecmp((char*)buf, "EHLO", 4) != 0 && strncasecmp((char*)buf, "HELO", 4) != 0)) {
			syslog(LOG_DEBUG, "Terminating: Expected EHLO/HELO after StartTLS, but received: %.*s", (int)bytes, buf);
			tlsClose(tls);
			return;
		}

		if (!send_aem(0, tls, "250-"AEM_DOMAIN""AEM_SHLO_RESPONSE"\r\n", 6 + AEM_DOMAIN_LEN + AEM_SHLO_RESPONSE_LEN)) {
			syslog(LOG_NOTICE, "Terminating: Failed sending greeting following StartTLS");
			tlsClose(tls);
			return;
		}

		clientCert = mbedtls_ssl_get_peer_cert(tls);
		email.tlsInfo = getCertType(clientCert) | getTlsVersion(tls);
		email.tls_ciphersuite = mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(tls));

		bytes = recv_aem(0, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
	}

	size_t toCount = 0;
	char to[AEM_SMTP_MAX_TO][32];

	unsigned char *source = NULL;
	size_t lenSource = 0;

	for (int roundsDone = 0;; roundsDone++) {
		if (roundsDone > AEM_SMTP_MAX_ROUNDS) {
			smtp_respond(sock, tls, '4', '2', '1');
			smtp_fail(clientAddr, 200);
			break;
		}

		if (bytes < 4) {
			if (bytes < 1) syslog(LOG_DEBUG, "Terminating: Client closed connection (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreeting, email.greeting);
			else syslog(LOG_NOTICE, "Terminating: Invalid data received (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreeting, email.greeting);
			break;
		}

		if (bytes > 10 && strncasecmp((char*)buf, "MAIL FROM:", 10) == 0) {
			if (smtp_addr_sender(buf + 10, bytes - 10) != 0) {
				smtp_fail(clientAddr, 100);
				break;
			}
		}

		else if (bytes > 8 && strncasecmp((char*)buf, "RCPT TO:", 8) == 0) {
			if (email.lenEnvFrom < 1) {
				email.protocolViolation = true;

				if (!smtp_respond(sock, tls, '5', '0', '3')) {
					smtp_fail(clientAddr, 101);
					break;
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
				continue;
			}

			if (toCount >= AEM_SMTP_MAX_TO - 1) {
				if (!smtp_respond(sock, tls, '4', '5', '2')) { // Too many recipients
					smtp_fail(clientAddr, 104);
					break;
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
				continue;
			}

			if (smtp_addr_our(buf + 8, bytes - 8, to[toCount]) != 0) {
				if (!smtp_respond(sock, tls, '5', '5', '0')) {
					smtp_fail(clientAddr, 103);
					break;
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
				continue;
			}

			toCount++;
		}

		else if (strncasecmp((char*)buf, "RSET", 4) == 0) {
			email.rareCommands = true;

			email.lenEnvFrom = 0;
			toCount = 0;
		}

		else if (strncasecmp((char*)buf, "VRFY", 4) == 0) {
			email.rareCommands = true;

			if (!smtp_respond(sock, tls, '2', '5', '2')) { // 252 = Cannot VRFY user, but will accept message and attempt delivery
				smtp_fail(clientAddr, 105);
				break;
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
			continue;
		}

		else if (strncasecmp((char*)buf, "QUIT", 4) == 0) {
			smtp_respond(sock, tls, '2', '2', '1');
			break;
		}

		else if (strncasecmp((char*)buf, "DATA", 4) == 0) {
			if (email.lenEnvFrom < 1 || toCount < 1) {
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

			source = malloc(AEM_SMTP_MAX_SIZE_BODY + 1);
			if (source == NULL) {
				smtp_respond(sock, tls, '4', '2', '1');
				syslog(LOG_ERR, "Failed allocation");
				smtp_fail(clientAddr, 999);
				break;
			}

			source[0] = '\n';
			lenSource = 1;

			// Receive body/source
			while(1) {
				bytes = recv_aem(sock, tls, source + lenSource, AEM_SMTP_MAX_SIZE_BODY - lenSource);
				if (bytes < 1) break;

				lenSource += bytes;

				if (lenSource >= 5 && memcmp(source + lenSource - 5, "\r\n.\r\n", 5) == 0) {
					lenSource -= 5;
					break;
				}

				if (lenSource >= AEM_SMTP_MAX_SIZE_BODY) break;
			}

			if (!smtp_respond(sock, tls, '2', '5', '0')) {
				sodium_memzero(source, lenSource);
				free(source);
				smtp_fail(clientAddr, 150);
				break;
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_MAX_SIZE_CMD);
			if (bytes >= 4 && strncasecmp((char*)buf, "QUIT", 4) == 0) email.quitReceived = true;

			convertLineDots(source, &lenSource);
			source[lenSource] = '\0';

			if (getHeaders(source, &lenSource, &email) == 0) {
				moveHeader(email.head, &email.lenHead, "\nFrom:", 6, email.headerFrom, &email.lenHeaderFrom, 255);
				moveHeader(email.head, &email.lenHead, "\nMessage-ID:", 12, email.msgId, &email.lenMsgId, 255);
				moveHeader(email.head, &email.lenHead, "\nSubject:", 9, email.subject, &email.lenSubject, 255);
				moveHeader(email.head, &email.lenHead, "\nTo:", 4, email.headerTo, &email.lenHeaderTo, 127);

				char ct[256];
				uint8_t lenCt = 0;
				moveHeader(email.head, &email.lenHead, "\nContent-Type:", 14, (unsigned char*)ct, &lenCt, 255);
				ct[lenCt] = '\0';

				uint8_t lenHdrDate = 0;
				unsigned char hdrDate[256];
				moveHeader(email.head, &email.lenHead, "\nDate:", 6, hdrDate, &lenHdrDate, 255);
				hdrDate[lenHdrDate] = '\0';
				const time_t hdrTime = (lenHdrDate == 0) ? 0 : smtp_getTime((char*)hdrDate, &email.headerTz);

				if (hdrTime > 0) {
					// Store the difference between received and header timestamps (-18h .. +736s)
					const time_t timeDiff = (time_t)email.timestamp + 736 - hdrTime; // 736 = 2^16 % 3600
					email.headerTs = (timeDiff > UINT16_MAX) ? UINT16_MAX : ((timeDiff < 0) ? 0 : timeDiff);
				}

				uint8_t lenHdrMsgId = 0;
				unsigned char hdrMsgId[256];
				moveHeader(email.head, &email.lenHead, "\nMessage-ID:", 12, hdrMsgId, &lenHdrMsgId, 255);
				if (lenHdrMsgId > 0) {
					if (hdrMsgId[lenHdrMsgId - 1] == '>') lenHdrMsgId--;
					if (hdrMsgId[0] == '<') {
						memcpy(email.msgId, hdrMsgId + 1, lenHdrMsgId - 1);
						email.lenMsgId = lenHdrMsgId - 1;
					} else {
						memcpy(email.msgId, hdrMsgId, lenHdrMsgId);
						email.lenMsgId = lenHdrMsgId;
					}
				}

				// Content-Type
				if (strncmp(ct, "multipart", 9) == 0) {
					const char *boundStart = strcasestr(ct + 9, "boundary=");
					if (boundStart != NULL) {
						char *boundEnd = NULL;
						boundStart += 9;

						if (*boundStart == '"') {
							boundStart++;
							boundEnd = strchr(boundStart, '"');
						} else if (*boundStart == '\'') {
							boundStart++;
							boundEnd = strchr(boundStart, '\'');
						} else {
							boundEnd = strpbrk(boundStart, "; \t\v\f\r\n");
						}

						const size_t lenBound = ((boundEnd != NULL) ? boundEnd : ((char*)email.head + email.lenHead)) - boundStart + 2;
						unsigned char *bound = malloc(lenBound);
						bound[0] = '-';
						bound[1] = '-';
						memcpy(bound + 2, boundStart, lenBound - 2);

						email.lenBody = lenSource;
						email.body = decodeMp(source, &(email.lenBody), &email, bound, lenBound);
						if (email.body == NULL) {
							email.body = source;
							email.lenBody = lenSource;
						} else free(source);
					} else { // Error - boundary string not found
						email.body = source;
						email.lenBody = lenSource;
					}
				} else { // Single-part body
					email.body = source;
					email.lenBody = lenSource;

					char tmp[256];
					uint8_t lenTmp = 0;
					moveHeader(email.head, &email.lenHead, "\nContent-Transfer-Encoding:", 27, (unsigned char*)tmp, &lenTmp, 255);
					tmp[lenTmp] = '\0';

					int cte;
					if (strcasestr(tmp, "quoted-printable") != 0) cte = MTA_PROCESSING_CTE_QP;
					else if (strcasestr(tmp, "base64") != 0) cte = MTA_PROCESSING_CTE_B64;
					else cte = 0;

					unsigned char * const new = decodeCte(cte, email.body, &email.lenBody);
					if (new != NULL) {
						free(email.body);
						email.body = new;
					}

					// TODO: charset conversion

					convertNbsp(email.body, &email.lenBody);
					removeControlChars(email.body, &email.lenBody);
					trimSpace(email.body, &email.lenBody);
					removeSpaceEnd(email.body, &email.lenBody);
					trimLinebreaks(email.body, &email.lenBody);
					removeSpaceBegin(email.body, &email.lenBody);
					trimEnd(email.body, &email.lenBody);
				}
			}

			getIpInfo();
			getCertNames(clientCert);

			deliverMessage(to, toCount, &email);

			sodium_memzero(email.head, email.lenHead);
			sodium_memzero(email.body, email.lenBody);
			free(email.head);
			free(email.body);

			for (int i = 0; i < email.attachCount; i++) {
				if (email.attachment[i] == NULL) break;
				free(email.attachment[i]);
			}

			sodium_memzero(&email, sizeof(struct emailInfo));

			sodium_memzero(to, 32 * AEM_SMTP_MAX_TO);
			toCount = 0;

			if (bytes < 1) break;
			continue;
		}

		else if (strncasecmp((char*)buf, "NOOP", 4) == 0) {
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
