#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <brotli/encode.h>
#include <mbedtls/pk.h>
#include <sodium.h>

#include "../Common/Addr32.h"
#include "../Common/Trim.h"
#include "../Common/UnixSocketClient.h"

#include "delivery.h"
#include "dkim.h"
#include "processing.h"

#include "smtp.h"

#include "../Global.h"

#define AEM_SMTP_MAX_SIZE_CMD 512 // RFC5321: min. 512
#define AEM_SMTP_MAX_SIZE_BODY 4194304 // 4 MiB. RFC5321: min. 64k; XXX if changed, set the HLO responses and their lengths below also
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

void setSignKey_mta(const unsigned char * const seed) {
	return setSignKey(seed);
}

void delSignKey_mta() {
	return delSignKey();
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

static void getCertName(const mbedtls_x509_crt * const cert) {
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

		if (name == NULL || lenName < 4) continue; // a.bc

		if (memcmp(name, "*.", 2) == 0) { // Wildcard: remove the asterisk and see if the ends match
			lenName--;
			name++;

			if (lenName < lenHdrFr       && memcmp(hdrFr       + lenHdrFr       - lenName, name, lenName) == 0) {email.tlsInfo |= AEM_EMAIL_CERT_MATCH_HDRFR; break;}
			if (lenName < lenEnvFr       && memcmp(envFr       + lenEnvFr       - lenName, name, lenName) == 0) {email.tlsInfo |= AEM_EMAIL_CERT_MATCH_ENVFR; break;}
			if (lenName < email.lenGreet && memcmp(email.greet + email.lenGreet - lenName, name, lenName) == 0) {email.tlsInfo |= AEM_EMAIL_CERT_MATCH_GREET; break;}
		} else {
			if      (lenName == lenHdrFr       && memcmp(name, hdrFr,       lenName) == 0) {email.tlsInfo |= AEM_EMAIL_CERT_MATCH_HDRFR; break;}
			else if (lenName == lenEnvFr       && memcmp(name, envFr,       lenName) == 0) {email.tlsInfo |= AEM_EMAIL_CERT_MATCH_ENVFR; break;}
			else if (lenName == email.lenGreet && memcmp(name, email.greet, lenName) == 0) {email.tlsInfo |= AEM_EMAIL_CERT_MATCH_GREET; break;}
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

	unsigned char ipInfo[130];
	int lenIpInfo = recv(sock, ipInfo, 130, 0);
	close(sock);
	if (lenIpInfo < 4) return;

	memcpy(email.ccBytes, ipInfo, 2);

	if (ipInfo[2] > 0) {
		email.lenRvDns = ipInfo[2];
		if (email.lenRvDns > 63) email.lenRvDns = 63;
		memcpy(email.rvDns, ipInfo + 4, email.lenRvDns);
	}

	if (ipInfo[3] > 0) {
		email.lenAuSys = ipInfo[3];
		if (email.lenAuSys > 63) email.lenAuSys = 63;
		memcpy(email.auSys, ipInfo + 4 + email.lenRvDns, email.lenAuSys);
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

static int getUpk(const char * const addr, const size_t addrChars, unsigned char * const upk, unsigned char * const addrFlags) {
	unsigned char addr32[10];
	addr32_store(addr32, addr, addrChars);

	const int sock = accountSocket((addrChars == 16) ? AEM_MTA_GETPUBKEY_SHIELD : AEM_MTA_GETPUBKEY_NORMAL, addr32, 10);
	if (sock < 0) return AEM_SMTP_ERROR_ADDR_OUR_INTERNAL;

	int ret = recv(sock, upk, crypto_box_PUBLICKEYBYTES, 0);
	if (ret == 1 && *upk == AEM_INTERNAL_RESPONSE_NOTEXIST) return AEM_SMTP_ERROR_ADDR_OUR_USER;
	if (ret != crypto_box_PUBLICKEYBYTES) return AEM_SMTP_ERROR_ADDR_OUR_INTERNAL;

	ret = (recv(sock, addrFlags, 1, 0) == 1) ? 0 : AEM_SMTP_ERROR_ADDR_OUR_USER;
	close(sock);
	return ret;
}

__attribute__((warn_unused_result))
static int smtp_addr_our(const unsigned char * const buf, const size_t len, char to[32], unsigned char * const toUpk, unsigned char * const addrFlags, const bool usingTls) {
	if (buf == NULL || len < 1) return AEM_SMTP_ERROR_ADDR_OUR_INTERNAL;

	size_t skipBytes = 0;
	while (skipBytes < len && isspace(buf[skipBytes])) skipBytes++;
	if (skipBytes >= len) return AEM_SMTP_ERROR_ADDR_OUR_SYNTAX;

	if (buf[skipBytes] != '<') return AEM_SMTP_ERROR_ADDR_OUR_SYNTAX;
	skipBytes++;

	const int max = len - skipBytes - 1;
	int lenAddr = 0;
	while (lenAddr < max && buf[skipBytes + lenAddr] != '>') lenAddr++;

	if (lenAddr < 1) return AEM_SMTP_ERROR_ADDR_OUR_USER;

	char addr[AEM_MAXLEN_ADDR32];
	int addrChars = 0;
	int toChars = 0;
	for (int i = 0; i < lenAddr; i++) {
		if (buf[skipBytes + i] == '@') {
			if (lenAddr - i - 1 != AEM_DOMAIN_LEN || strncasecmp((char*)buf + skipBytes + i + 1, AEM_DOMAIN, AEM_DOMAIN_LEN) != 0) return AEM_SMTP_ERROR_ADDR_OUR_DOMAIN;
			break;
		}

		if (toChars >= 31) return AEM_SMTP_ERROR_ADDR_OUR_USER;
		to[toChars] = buf[skipBytes + i];
		toChars++;

		if (isalnum(buf[skipBytes + i])) {
			if (addrChars + 1 > AEM_MAXLEN_ADDR32) return AEM_SMTP_ERROR_ADDR_OUR_USER;
			addr[addrChars] = tolower(buf[skipBytes + i]);
			addrChars++;
		}
	}

	if (addrChars < 1 || addrChars > 16
	|| (addrChars == 6 && memcmp(addr, "system", 6) == 0)
	|| (addrChars == 6 && memcmp(addr, "public", 6) == 0)
	|| (addrChars == 16 && memcmp(addr + 3, "administrator", 13) == 0)
	) return AEM_SMTP_ERROR_ADDR_OUR_USER;

	to[toChars] = '\0';
	const int ret = getUpk(addr, addrChars, toUpk, addrFlags);
	if (ret != 0) return ret;
	if (!usingTls && (*addrFlags & AEM_ADDR_FLAG_SECURE) != 0) return AEM_SMTP_ERROR_ADDR_TLS_NEEDED;
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

static void smtp_fail(const int code) {
	syslog((code < 10 ? LOG_DEBUG : LOG_NOTICE), "Error receiving message (Code: %d, IP: %u.%u.%u.%u)", code, ((uint8_t*)&email.ip)[0], ((uint8_t*)&email.ip)[1], ((uint8_t*)&email.ip)[2], ((uint8_t*)&email.ip)[3]);
}

static void prepareEmail(unsigned char * const source, size_t lenSource) {
	convertLineDots(source, &lenSource);
	getIpInfo();
	email.ipMatchGreeting = greetingDomainMatchesIp(email.ip);
	email.ipBlacklisted = isIpBlacklisted(email.ip);

	// Add final CRLF for DKIM
	source[lenSource + 0] = '\r';
	source[lenSource + 1] = '\n';
	source[lenSource + 2] = '\0';
	lenSource += 2;

	for (int i = 0; i < 7; i++) {
		const unsigned char * const headersEnd = memmem(source, lenSource, "\r\n\r\n", 4);
		if (headersEnd == NULL) break;

		unsigned char *start = (unsigned char*)strcasestr((char*)source, "\nDKIM-Signature:");
		if (start == NULL || start > headersEnd) break;
		start++;
		const int offset = verifyDkim(&email, start, (source + lenSource) - start);
		if (offset == 0) break;

		// Delete the signature from the headers
		memmove(start, start + offset, (source + lenSource) - (start + offset));
		lenSource -= offset;
		source[lenSource] = '\0';
	}

	// Remove final CRLF
	lenSource -= 2;
	source[lenSource] = '\0';

	processEmail(source, &lenSource, &email);
}

static void clearEmail(void) {
	if (email.head != NULL) {
		sodium_memzero(email.head, email.lenHead);
		free(email.head);
	}

	if (email.body != NULL) {
		sodium_memzero(email.body, email.lenBody);
		free(email.body);
	}

	for (int i = 0; i < email.attachCount; i++) {
		if (email.attachment[i] == NULL) break;
		free(email.attachment[i]);
	}

	sodium_memzero(&email, sizeof(struct emailInfo));
}

void respondClient(int sock, const struct sockaddr_in * const clientAddr) {
	if (sock < 0 || clientAddr == NULL) return;
	bzero(&email, sizeof(struct emailInfo));
	email.timestamp = (uint32_t)time(NULL);
	email.ip = clientAddr->sin_addr.s_addr;

	if (!send_aem(sock, NULL, "220 "AEM_DOMAIN"\r\n", 6 + AEM_DOMAIN_LEN)) return smtp_fail(0);

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

	if (bytes >= 8 && strncasecmp((char*)buf, "STARTTLS", 8) == 0) {
		bytes = recv(sock, buf, AEM_SMTP_MAX_SIZE_CMD, 0); // Remove the MSG_PEEK'd message from the queue
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
		} else if (bytes >= 4 && strncasecmp((char*)buf, "QUIT", 4) == 0) {
			syslog(LOG_DEBUG, "Terminating: Client closed connection cleanly after StartTLS (IP: %s; greeting: %.*s)", inet_ntoa(clientAddr->sin_addr), email.lenGreet, email.greet);
			send_aem(sock, tls, "221 Bye\r\n", 9);
			tlsClose(tls);
			return;
		} else if (bytes < 4 || (strncasecmp((char*)buf, "EHLO", 4) != 0 && strncasecmp((char*)buf, "HELO", 4) != 0)) {
			syslog(LOG_DEBUG, "Terminating: Expected EHLO/HELO after StartTLS, but received: %.*s", (int)bytes, buf);
			send_aem(sock, tls, "421 5.5.1 EHLO/HELO required after STARTTLS\r\n", 45);
			tlsClose(tls);
			return;
		}

		if (!send_aem(0, tls, "250-"AEM_DOMAIN""AEM_SHLO_RESPONSE"\r\n", 6 + AEM_DOMAIN_LEN + AEM_SHLO_RESPONSE_LEN)) {
			syslog(LOG_NOTICE, "Terminating: Failed sending greeting following StartTLS");
			tlsClose(tls);
			return;
		}

		const mbedtls_x509_crt *clientCert = mbedtls_ssl_get_peer_cert(tls);
		email.tlsInfo = getCertType(clientCert) | getTlsVersion(tls);
		getCertName(clientCert);
		email.tls_ciphersuite = mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(tls));
	}

	bool storeOriginal = false;
	size_t toCount = 0;
	char to[AEM_SMTP_MAX_TO][32];
	unsigned char toUpk[AEM_SMTP_MAX_TO][crypto_box_PUBLICKEYBYTES];
	unsigned char toFlags[AEM_SMTP_MAX_TO];

	unsigned char *source = NULL;
	size_t lenSource = 0;

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
		} else if (bytes > 10 && strncasecmp((char*)buf, "MAIL FROM:", 10) == 0) {
			if (smtp_addr_sender(buf + 10, bytes - 10) != 0) {smtp_fail(100); break;}
			if (!send_aem(sock, tls, "250 2.1.0 Sender address ok\r\n", 29)) {smtp_fail(101); break;}
		} else if (bytes > 8 && strncasecmp((char*)buf, "RCPT TO:", 8) == 0) {
			if (email.lenEnvFr < 1) {
				email.protocolViolation = true;
				if (!send_aem(sock, tls, "503 5.5.1 Need sender address first\r\n", 37)) {smtp_fail(102); break;}
				continue;
			}

			if (toCount >= AEM_SMTP_MAX_TO - 1) {
				if (!send_aem(sock, tls, "451 5.5.3 Too many recipients\r\n", 31)) {smtp_fail(103); break;}
				continue;
			}

			bool retOk;
			switch (smtp_addr_our(buf + 8, bytes - 8, to[toCount], toUpk[toCount], &toFlags[toCount], tls != NULL)) {
				case 0: retOk = send_aem(sock, tls, "250 2.1.5 Recipient address ok\r\n", 32); break;
				case AEM_SMTP_ERROR_ADDR_OUR_USER:   retOk = send_aem(sock, tls, "550 5.1.1 No such user\r\n", 24); break;
				case AEM_SMTP_ERROR_ADDR_OUR_DOMAIN: retOk = send_aem(sock, tls, "550 5.1.2 Not our domain\r\n", 26); break;
				case AEM_SMTP_ERROR_ADDR_OUR_SYNTAX: retOk = send_aem(sock, tls, "501 5.1.3 Invalid address\r\n", 27); break;
				case AEM_SMTP_ERROR_ADDR_TLS_NEEDED: retOk = send_aem(sock, tls, "450 4.7.0 Recipient requires secure transport (TLS)\r\n", 53); break;
				default: retOk = send_aem(sock, tls, "451 4.3.0 Internal server error\r\n", 33);
			}
			if (!retOk) {smtp_fail(104); break;}

			if ((toFlags[toCount] & AEM_ADDR_FLAG_ORIGIN) != 0) storeOriginal = true;
			toCount++;
		} else if (strncasecmp((char*)buf, "RSET", 4) == 0) {
			email.rareCommands = true;
			email.lenEnvFr = 0;
			toCount = 0;
			if (!send_aem(sock, tls, "250 Reset\r\n", 11)) {smtp_fail(150); break;}
		} else if (strncasecmp((char*)buf, "VRFY", 4) == 0) {
			email.rareCommands = true;
			if (!send_aem(sock, tls, "252 Not verified\r\n", 18)) {smtp_fail(105); break;}
		} else if (strncasecmp((char*)buf, "QUIT", 4) == 0) {
			send_aem(sock, tls, "221 Bye\r\n", 9);
			break;
		} else if (strncasecmp((char*)buf, "DATA", 4) == 0) {
			if (email.lenEnvFr < 1 || toCount < 1) {
				email.protocolViolation = true;

				bool retOk;
				if (email.lenEnvFr < 1 && toCount < 1) {retOk = send_aem(sock, tls, "503 5.5.1 Need recipient and sender addresses first\r\n", 53);}
				else if (email.lenEnvFr < 1)           {retOk = send_aem(sock, tls, "503 5.5.1 Need sender address first\r\n", 37);}
				else                                   {retOk = send_aem(sock, tls, "503 5.5.1 Need recipient address first\r\n", 40);}
				if (!retOk) {smtp_fail(106); break;}

				continue;
			}

			if (!send_aem(sock, tls, "354 Ok\r\n", 8)) {smtp_fail(107); break;}

			source = malloc(AEM_SMTP_MAX_SIZE_BODY + 5);
			if (source == NULL) {
				send_aem(sock, tls, "421 4.3.0 Internal server error\r\n", 33);
				syslog(LOG_ERR, "Failed allocation");
				smtp_fail(999);
				break;
			}

			source[0] = '\n';
			lenSource = 1;

			// Receive body/source
			while(1) {
				bytes = recv_aem(sock, tls, source + lenSource, AEM_SMTP_MAX_SIZE_BODY - lenSource);
				if (bytes < 1) break;

				lenSource += bytes;

				const unsigned char * const end = (lenSource < 5) ? NULL : memmem(source, lenSource, "\r\n.\r\n", 5);
				if (end != NULL) {
					lenSource = end - source;
					break;
				}

				if (lenSource >= AEM_SMTP_MAX_SIZE_BODY) break;
			}

			bool brOriginal = false;
			size_t lenOriginal = lenSource - 1;
			unsigned char *original = NULL;
			if (storeOriginal && 17 + 7 + lenOriginal <= AEM_API_BOX_SIZE_MAX) { // 7 = Filename length
				original = malloc(lenOriginal);
				if (original != NULL) {
					size_t lenComp = lenOriginal;
					if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_DEFAULT_MODE, lenOriginal, source + 1, &lenComp, original) != BROTLI_FALSE) {
						lenOriginal = lenComp;
						brOriginal = true;
					} else {
						memcpy(original, source + 1, lenOriginal);
						syslog(LOG_ERR, "Failed compression");
					}
				} else syslog(LOG_ERR, "Failed allocation");
			}

			prepareEmail(source, lenSource);
			const int deliveryStatus = deliverMessage(to, toUpk, toFlags, toCount, &email, original, lenOriginal, brOriginal);

			if (original != NULL) free(original);
			clearEmail();
			sodium_memzero(to,      AEM_SMTP_MAX_TO * 32);
			sodium_memzero(toUpk,   AEM_SMTP_MAX_TO * crypto_box_PUBLICKEYBYTES);
			sodium_memzero(toFlags, AEM_SMTP_MAX_TO);
			toCount = 0;

			bool retOk;
			switch (deliveryStatus) {
				case SMTP_STORE_INERROR: retOk = send_aem(sock, tls, "451 4.3.0 Internal server error\r\n", 33); break;
				case SMTP_STORE_USRFULL: retOk = send_aem(sock, tls, "452 4.2.2 Recipient mailbox full\r\n", 34); break;
				case SMTP_STORE_MSGSIZE: retOk = send_aem(sock, tls, "554 5.3.4 Message too big\r\n", 27); break;
				default: retOk = send_aem(sock, tls, "250 Message delivered\r\n", 23);
			}
			if (!retOk) {smtp_fail(108); break;}
		} else if (strncasecmp((char*)buf, "NOOP", 4) == 0) {
			email.rareCommands = true;
			if (!send_aem(sock, tls, "250 Ok\r\n", 8)) {smtp_fail(150); break;}
		} else { // Unsupported commands
			email.invalidCommands = true;
			if (!send_aem(sock, tls, "500 5.5.1 Command unsupported\r\n", 31)) {smtp_fail(109); break;}
		}
	}

	tlsClose(tls);
}
