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
#include "../Common/HtmlToText.h"
#include "../Common/QuotedPrintable.h"
#include "../Common/ToUtf8.h"
#include "../Common/Trim.h"
#include "../Common/UnixSocketClient.h"

#include "delivery.h"
#include "dkim.h"
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

	size_t lenEnvFr = 0;
	const unsigned char *envFr = memchr(email.envFr, '@', email.lenEnvFr);
	if (envFr != NULL) {
		envFr++;
		lenEnvFr = email.lenEnvFr - (envFr - email.envFr);
	}

	size_t lenHdrFr = 0;
	const unsigned char *hdrFr = memchr(email.hdrFr, '@', email.lenHdrFr);
	if (hdrFr != NULL) {
		hdrFr++;
		lenHdrFr = email.lenHdrFr - (hdrFr - email.hdrFr);
	}

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
			if      (lenName == lenHdrFr       && memcmp(name, hdrFr,       lenName) == 0) {email.tlsInfo = AEM_EMAIL_CERT_MATCH_HDRFR; break;}
			else if (lenName == lenEnvFr       && memcmp(name, envFr,       lenName) == 0) {email.tlsInfo = AEM_EMAIL_CERT_MATCH_ENVFR; break;}
			else if (lenName == email.lenRvDns && memcmp(name, email.rvDns, lenName) == 0) {email.tlsInfo = AEM_EMAIL_CERT_MATCH_RVDNS; break;}
			else if (lenName == email.lenGreet && memcmp(name, email.greet, lenName) == 0) {email.tlsInfo = AEM_EMAIL_CERT_MATCH_GREET; break;}
			else syslog(LOG_INFO, "<%.*s>", (int)lenName, name);
		}
	}
}

static void getIpInfo(void) {
	email.lenRvDns = 0;
	email.ccBytes[0] |= 31;
	email.ccBytes[1] |= 31;

	const int sock = enquirySocket(AEM_ENQUIRY_IP, (unsigned char*)&email.ip, 4);
	if (sock < 0) {
		syslog(LOG_ERR, "Failed connecting to Enquiry");
		return;
	}

	unsigned char ipInfo[129];
	const int lenIpInfo = recv(sock, ipInfo, 129, 0);
	close(sock);
	if (lenIpInfo < 2) return;

	memcpy(email.ccBytes, ipInfo, 2);

	if (lenIpInfo > 2) {
		email.lenRvDns = lenIpInfo - 2;
		memcpy(email.rvDns, ipInfo + 2, email.lenRvDns);
	}
}

static bool isIpBlacklisted(const uint32_t ip) {
	char dnsbl_domain[17 + AEM_MTA_DNSBL_LEN];
	sprintf(dnsbl_domain, "%u.%u.%u.%u."AEM_MTA_DNSBL, ((uint8_t*)&ip)[3], ((uint8_t*)&ip)[2], ((uint8_t*)&ip)[1], ((uint8_t*)&ip)[0]);

	const int sock = enquirySocket(AEM_ENQUIRY_A, (unsigned char*)dnsbl_domain, strlen(dnsbl_domain));
	if (sock < 0) {
		syslog(LOG_ERR, "Failed connecting to Enquiry");
		return false;
	}

	uint32_t dnsbl_ip = 0;
	const int lenIpInfo = recv(sock, &dnsbl_ip, 4, 0);
	close(sock);
	return (lenIpInfo == sizeof(uint32_t) && dnsbl_ip == 1);
}

static bool greetingDomainMatchesIp(const uint32_t ip_conn) {
	const int sock = enquirySocket(AEM_ENQUIRY_A, email.greet, email.lenGreet);
	if (sock < 0) {
		syslog(LOG_ERR, "Failed connecting to Enquiry");
		return false;
	}

	uint32_t ip_greet;
	const int lenRecv = recv(sock, &ip_greet, sizeof(uint32_t), 0);
	close(sock);

	return (lenRecv == sizeof(uint32_t) && ip_greet == ip_conn);
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

	email.lenGreet = bytes - 7;
	if (email.lenGreet > 127) email.lenGreet = 127;
	memcpy(email.greet, buf + 5, email.lenGreet);

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
			syslog(LOG_DEBUG, "Terminating: Client closed connection after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreet, email.greet);
			tlsClose(tls);
			return;
		} else if (bytes >= 4 && strncasecmp((char*)buf, "QUIT", 4) == 0) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection cleanly after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreet, email.greet);
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
			if (bytes < 1) syslog(LOG_DEBUG, "Terminating: Client closed connection (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreet, email.greet);
			else syslog(LOG_NOTICE, "Terminating: Invalid data received (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreet, email.greet);
			break;
		}

		if (bytes > 10 && strncasecmp((char*)buf, "MAIL FROM:", 10) == 0) {
			if (smtp_addr_sender(buf + 10, bytes - 10) != 0) {
				smtp_fail(clientAddr, 100);
				break;
			}
		}

		else if (bytes > 8 && strncasecmp((char*)buf, "RCPT TO:", 8) == 0) {
			if (email.lenEnvFr < 1) {
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

			email.lenEnvFr = 0;
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
			if (email.lenEnvFr < 1 || toCount < 1) {
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
					lenSource -= 3;
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

			for (int i = 0; i < 7; i++) {
				const unsigned char * const headersEnd = memmem(source, lenSource, "\r\n\r\n", 4);
				if (headersEnd == NULL) break;

				unsigned char * const start = (unsigned char*)strcasestr((char*)source, "DKIM-Signature:");
				if (start == NULL || start > headersEnd) break;
				const int offset = verifyDkim(&email, start, (source + lenSource) - start);
				if (offset == 0) break;

				// Delete the signature from the headers
				memmove(start, start + offset, (source + lenSource) - (start + offset));
				lenSource -= offset;
				source[lenSource] = '\0';
			}

			processEmail(source, &lenSource, &email);

			getIpInfo();
			email.greetingIpMatch = greetingDomainMatchesIp(clientAddr->sin_addr.s_addr);
			email.ipBlacklisted = isIpBlacklisted(clientAddr->sin_addr.s_addr);
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
