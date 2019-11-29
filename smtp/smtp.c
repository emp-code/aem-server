#define _GNU_SOURCE // for memmem

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <maxminddb.h>
#include <sodium.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "Include/Addr32.h"
#include "Include/Base64.h"
#include "Include/Brotli.h"
#include "Include/CharToInt64.h"
#include "Include/Database.h"
#include "Include/Message.h"
#include "Include/QuotedPrintable.h"
#include "Include/ToUtf8.h"

#include "smtp.h"

#define AEM_MAXLEN_DOMAIN 32

#define AEM_SMTP_SIZE_CMD 512 // RFC5321: min. 512

#define AEM_SMTP_MAX_ADDRSIZE 200
#define AEM_SMTP_MAX_ADDRSIZE_TO 5000 // RFC5321: must accept 100 recipients at minimum

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
static int16_t getCountryCode(const struct sockaddr * const sockAddr) {
	if (sockAddr == NULL) return 0;

	MMDB_s mmdb;
	int status = MMDB_open("GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb);

	if (status != MMDB_SUCCESS) {
		printf("getCountryCode: Can't open database: %s\n", MMDB_strerror(status));
		return 0;
	}

	int mmdb_error;
	MMDB_lookup_result_s mmdb_result = MMDB_lookup_sockaddr(&mmdb, sockAddr, &mmdb_error);

	if (mmdb_error != MMDB_SUCCESS) {
		printf("getCountryCode: Got an error from libmaxminddb: %s\n", MMDB_strerror(mmdb_error));
		return 0;
	}

	int16_t ret = 0;
	if (mmdb_result.found_entry) {
		MMDB_entry_data_s entry_data;
		status = MMDB_get_value(&mmdb_result.entry, &entry_data, "country", "iso_code", NULL);

		if (status == MMDB_SUCCESS) {
			memcpy(&ret, entry_data.utf8_string, 2);
		} else {
			printf("getCountryCode: Error looking up the entry data: %s\n", MMDB_strerror(status));
		}
	} else puts("getCountryCode: No entry for the IP address was found");

	MMDB_close(&mmdb);
	return ret;
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

	if (sock > 0) return (send(sock, data, lenData, 0) == (int)lenData);

	return false;
}

static bool smtp_respond(const int sock, mbedtls_ssl_context * const tls, const char code1, const char code2, const char code3) {
	const char resp[9] = {code1, code2, code3, ' ', 'a', 'e', 'm', '\r', '\n'};
	return send_aem(sock, tls, resp, 9);
}

__attribute__((warn_unused_result))
static size_t smtp_addr(const char * const buf, const size_t len, char * const addr) {
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
static bool smtp_greet(const int sock, const char * const domain, const size_t lenDomain) {
	if (domain == NULL || lenDomain < 1) return false;

	const int lenGreet = 12 + lenDomain;
	char ourGreeting[lenGreet];
	memcpy(ourGreeting, "220 ", 4);
	memcpy(ourGreeting + 4, domain, lenDomain);
	memcpy(ourGreeting + 4 + lenDomain, " ESMTP\r\n", 8);
	return (send(sock, ourGreeting, lenGreet, 0) == lenGreet);
}

__attribute__((warn_unused_result))
static bool smtp_shlo(mbedtls_ssl_context * const tls, const char * const domain, const size_t lenDomain) {
	if (tls == NULL || domain == NULL || lenDomain < 1) return false;

	const ssize_t lenShlo = 4 + lenDomain + AEM_SHLO_RESPONSE_LEN;
	char shlo[lenShlo];
	memcpy(shlo, "250-", 4);
	memcpy(shlo + 4, domain, lenDomain);
	memcpy(shlo + 4 + lenDomain, AEM_SHLO_RESPONSE, AEM_SHLO_RESPONSE_LEN);
	return send_aem(0, tls, shlo, lenShlo);
}

__attribute__((warn_unused_result))
static bool smtp_helo(const int sock, const char * const domain, const size_t lenDomain, const char * const buf, const ssize_t bytes) {
	if (domain == NULL || lenDomain < 1 || buf == NULL || bytes < 4) return false;

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
	printf("Error receiving message (Code: %d, IP: %s)\n", code, inet_ntoa(clientAddr->sin_addr));
}

void tlsFree(void) {
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}

static void deliverMessage(const char * const to, const size_t lenToTotal, const char * const from, const size_t lenFrom, const char * const msgBody, const size_t lenMsgBody,
const struct sockaddr_in * const sockAddr, const int cs, const uint8_t tlsVersion, const unsigned char infoByte) {
	if (to == NULL || lenToTotal < 1 || from == NULL || lenFrom < 1 || msgBody == NULL || lenMsgBody < 1 || sockAddr == NULL) return;

	const char *toStart = to;
	const char * const toEnd = to + lenToTotal;

	while(1) {
		char * const nextTo = memchr(toStart, '\n', toEnd - toStart);
		const size_t lenTo = ((nextTo != NULL) ? nextTo : toEnd) - toStart;
		if (lenTo < 1) break;

		unsigned char binTo[15];
		addr32_store(binTo, toStart, lenTo);

		unsigned char pk[crypto_box_PUBLICKEYBYTES];
		unsigned char flags;
		int ret = getPublicKeyFromAddress(binTo, pk, &flags);
		if (ret != 0 || !(flags & AEM_FLAGS_ADDR_ACC_EXTMSG)) {
			if (nextTo == NULL) return;
			toStart = nextTo + 1;
			continue;
		}

		const char *domain = strchr(from, '@');
		if (domain == NULL) return;
		domain++;
		const size_t lenDomain = (from + lenFrom) - domain;

		const uint8_t attach = 0; // TODO
		const uint8_t spamByte = 0; // TODO
		const int16_t geoId = getCountryCode((struct sockaddr*)sockAddr);

		if (flags & AEM_FLAGS_ADDR_USE_GK && isBlockedByGatekeeper(&geoId, domain, lenDomain, from, lenFrom, charToInt64(pk))) return;

		size_t bodyLen = lenMsgBody;
		unsigned char * const boxSet = makeMsg_Ext(pk, binTo, msgBody, &bodyLen, sockAddr->sin_addr.s_addr, cs, tlsVersion, geoId, attach, infoByte, spamByte);
		const size_t bsLen = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + bodyLen + crypto_box_SEALBYTES;

		if (boxSet == NULL) {
			puts("Failed to deliver email: makeMsg_Ext failed");
			toStart = nextTo + 1;
			continue;
		}

		ret = addUserMessage(charToInt64(pk), boxSet, bsLen);
		free(boxSet);
		if (ret != 0) puts("Failed to deliver email: addUserMessage failed");

		if (nextTo == NULL) return;
		toStart = nextTo + 1;
	}
}

void decodeEncodedWord(char * const data, size_t * const lenData) {
	if (data == NULL || lenData == NULL || *lenData < 1) return;

	while(1) {
		const char * const headersEnd = memmem(data, *lenData, "\r\n\r\n", 4);
		if (headersEnd == NULL) break;

		const size_t searchLen = headersEnd - data;
		char * const ew = memmem(data, searchLen, "=?", 2);
		if (ew == NULL) break;

		// Remove charset part
		char * const charsetEnd = memchr(ew + 2, '?', (data + *lenData) - (ew + 2));
		if (charsetEnd == NULL) return;
		if (charsetEnd[2] != '?') return;

		const size_t csLen = charsetEnd - (ew + 2);
		char cs[csLen + 1];
		memcpy(cs, (ew + 2), csLen);
		cs[csLen] = '\0';

		const char type = charsetEnd[1];
		char *ewText = charsetEnd + 3;

		const char * const ewEnd = memmem(charsetEnd + 3, *lenData - (ewText - data), "?=", 2);
		if (ewEnd == NULL) break;

		size_t lenEw = ewEnd - ew;
		size_t lenEwText = ewEnd - ewText;

		while(1) {
			char * const underscore = memchr(ewText, '_', lenEwText);
			if (underscore == NULL) break;
			*underscore = ' ';
		}

		if (type == 'Q' || type == 'q') {
			decodeQuotedPrintable(ewText, &lenEwText);
		} else if (type == 'B' || type == 'b') {
			unsigned char * const dec = b64Decode((const unsigned char*)ewText, lenEwText, &lenEwText);
			if (dec == NULL) return;

			memcpy(ewText, dec, lenEwText);
			free(dec);
		} else return;

		int lenUtf8 = 0;
		char *utf8 = toUtf8(ewText, lenEwText, &lenUtf8, cs);
		if (utf8 != NULL) {
			const int lenDiff = lenEw - lenUtf8;
			if (lenDiff > 0) {
				memcpy(ew, utf8, lenUtf8);
				memmove(ew + lenUtf8, ewEnd + 2, *lenData - (ewEnd + 2 - data));
				*lenData -= (lenDiff + 2);
			} else {
				// TODO: UTF-8 version is longer
				return;
			}

			free(utf8);
		}
	}
}

__attribute__((warn_unused_result))
static bool isAddressAem(const char * const c, const size_t len) {
	if (c == NULL || len < 1 || len > 24) return false;

	for (size_t i = 0; i < len; i++) {
		if (!isalnum(c[i])) return false;
	}

	return true;
}

__attribute__((warn_unused_result))
static bool isAddressOurs(const char * const addr, const size_t lenAddr, const char * const domain, const size_t lenDomain) {
	if (addr == NULL || lenAddr < 1 || domain == NULL || lenDomain < 1) return false;

	return (
	   lenAddr > (lenDomain + 1)
	&& addr[lenAddr - lenDomain - 1] == '@'
	&& strncasecmp(addr + lenAddr - lenDomain, domain, lenDomain) == 0
	&& isAddressAem(addr, lenAddr - lenDomain - 1)
	);
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

static void unfoldHeaders(char * const data, size_t * const lenData) {
	const char * const headersEnd = memmem(data, *lenData, "\r\n\r\n", 4);
	if (headersEnd == NULL) return;
	size_t lenHeaders = headersEnd - data;

	while(1) {
		char *crlfWsp = memmem(data + 2, lenHeaders, "\r\n ", 3);
		if (crlfWsp == NULL) crlfWsp = memmem(data + 2, lenHeaders, "\r\n\t", 3);
		if (crlfWsp == NULL) break;

		const size_t num = (memcmp(crlfWsp - 2, "?=", 2) == 0) ? 3 : 2; // Remove space if previous line ended with an Encoded-Word

		memmove(crlfWsp, crlfWsp + num, (data + *lenData) - (crlfWsp + num));

		*lenData -= num;
		lenHeaders -= num;
		data[*lenData] = '\0';
	}
}

static char *decodeMp(const char * const msg, size_t *outLen) {
	char *out = NULL;
	*outLen = 0;

	int boundCount = 0;
	char *b = strstr(msg, "Content-Type: multipart/");
	if (b == NULL) return NULL;

	while (1) {
		boundCount++;
		b = strstr(b + 24, "Content-Type: multipart/");
		if (b == NULL) break;
	}

	char* bound[boundCount];
	b = strstr(msg, "Content-Type: multipart/");

	for (int i = 0; i < boundCount; i++) {
		b = strcasestr(b, "boundary=");
		if (b == NULL) {boundCount = i; break;}
		b += 9;
		if (*b == '"') b++;

		const size_t len = strcspn(b, "\" \r\n");
		bound[i] = strndup(b - 2, len);
		memcpy(bound[i], "--", 2);

		b = strstr(b + 24, "Content-Type: multipart/");
		if (b == NULL) break;
	}

	const char *searchBegin = msg;
	for (int i = 0; i < boundCount;) {
		char *begin = strstr(searchBegin, bound[i]);
		if (begin == NULL) {i++; continue;}
		begin += strlen(bound[i]);

		const char *hend = strstr(begin, "\r\n\r\n");
		const char * const hend2 = strstr(begin, "\n\n");
		size_t lenHend;
		if (hend2 != NULL && (hend == NULL || hend2 < hend)) {
			hend = hend2;
			lenHend = 2;
		} else lenHend = 4;
		if (hend == NULL) break;

		const char *cte = strcasestr(begin, "\nContent-Transfer-Encoding: ");
		if (cte != NULL && cte < hend) {
			if (strncasecmp(cte + 28, "quoted-printable", 16) == 0) cte = "Q";
			else if (strncasecmp(cte + 28, "base64", 6) == 0) cte = "B";
			else cte = "X";
		} else cte = "X";

		const char *ct = strcasestr(begin, "\nContent-Type: ");
		if (ct == NULL || ct > hend) break;

		const char *boundEnd = strstr(hend + lenHend, bound[i]);

		if (strncasecmp(ct + 15, "text/", 5) == 0) {
			hend += lenHend;
			size_t lenNew = boundEnd - hend;

			char *charset = NULL;
			char *cs = strstr(ct + 15, "charset=");
			if (cs == NULL) cs = strstr(ct + 15, "harset =");
			if (cs != NULL && cs < hend) {
				cs += 8;
				if (*cs == ' ') cs++;
				if (*cs == '"') cs++;
				size_t lenCs = strcspn(cs, "\r\n \"'");
				charset = strndup(cs, lenCs);
			}

			char *new = NULL;

			if (*cte == 'Q') {
				new = strndup(hend, lenNew);
				if (new == NULL) {free(charset); break;}
				decodeQuotedPrintable(new, &lenNew);
			} else if (*cte == 'B') {
				new = (char*)b64Decode((unsigned char*)hend, lenNew, &lenNew);
				if (new == NULL) {free(charset); break;}
			} else {
				new = strndup(hend, lenNew);
			}

			// TODO: Support detecting charset if missing?
			if (charset != NULL && strncmp(charset, "utf8", 4) != 0 && strncmp(charset, "utf-8", 5) != 0 && strncmp(charset, "ascii", 5) != 0 && strncmp(charset, "us-ascii", 8) != 0) {
				int lenUtf8;
				char *utf8 = toUtf8(new, lenNew, &lenUtf8, charset);
				if (utf8 != NULL) {
					free(new);
					new = utf8;
					lenNew = (size_t)lenUtf8;
				}
			}

			if (charset != NULL) free(charset);

			char *out2 = realloc(out, *outLen + lenNew);
			if (out2 == NULL) break;

			out = out2;
			memcpy(out + *outLen, new, lenNew);
			*outLen += lenNew;

			free(new);
		}

		searchBegin = boundEnd;
	}

	for (int i = 0; i < boundCount; i++) free(bound[i]);

	return out;
}

static void decodeMessage(char ** const msg, size_t * const lenMsg) {
	char *headersEnd = memmem(*msg,  *lenMsg, "\r\n\r\n", 4);
	const char *z = memchr(*msg, '\0', *lenMsg);
	if (headersEnd == NULL || (z != NULL && z < headersEnd)) return;
	headersEnd += 4;

	char *h = strcasestr(*msg, "\nContent-Type: ");
	h += 15;

	if (strncasecmp(h, "multipart/", 10) == 0) {
		size_t lenNew;
		char *new = decodeMp(*msg, &lenNew);

		if (new != NULL) {
			size_t lenHeaders = headersEnd - *msg;

			const size_t lenFull = lenHeaders + lenNew;
			char *full = malloc(lenFull);

			memcpy(full, *msg, lenHeaders);
			memcpy(full + lenHeaders, new, lenNew);
			free(new);

			*lenMsg = lenFull;
			free(*msg);
			*msg = full;
		}
	} else {
		const char *cte = strcasestr(*msg, "\nContent-Transfer-Encoding: quoted-printable");
		if (cte != NULL && cte < headersEnd) {
			size_t len = (*lenMsg) - (headersEnd - *msg);
			const size_t lenOld = len;
			decodeQuotedPrintable(headersEnd, &len);
			const size_t lenDiff = lenOld - len;
			*lenMsg -= lenDiff;
		} else  {
			cte = strcasestr(*msg, "\nContent-Transfer-Encoding: base64");
			if (cte != NULL && cte < headersEnd) {
				const size_t lenOld = *lenMsg - (headersEnd - *msg);
				size_t len;
				unsigned char * const e = b64Decode((unsigned char*)headersEnd, lenOld, &len);
				if (e != NULL) {
					memcpy(headersEnd, e, len);
					const size_t lenDiff = lenOld - len;
					*lenMsg -= lenDiff;
					free(e);
				}
			}
		}
	}
}

int tlsSetup(mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey) {
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	int ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		printf("mbedtls_ssl_config_defaults returned %d\n", ret);
		return -1;
	}

	mbedtls_ssl_conf_arc4_support(&conf, MBEDTLS_SSL_ARC4_ENABLED);
	mbedtls_ssl_conf_ciphersuites(&conf, smtp_ciphersuites);
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1); // Require TLS v1.0+
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret != 0) {
		printf("mbedtls_ctr_drbg_seed returned %d\n", ret);
		return -1;
	}

	ret = mbedtls_ssl_conf_own_cert(&conf, tlsCert, tlsKey);
	if (ret != 0) {
		printf("mbedtls_ssl_conf_own_cert returned %d\n", ret);
		return -1;
	}

	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {
		printf("mbedtls_ssl_setup returned %d\n", ret);
		return -1;
	}

	return 0;
}

void respond_smtp(int sock, const struct sockaddr_in * const clientAddr) {
	if (sock < 0 || domain == NULL || lenDomain < 1 || clientAddr == NULL) return;

	if (!smtp_greet(sock, domain, lenDomain)) return smtp_fail(NULL, clientAddr, 0);

	char buf[AEM_SMTP_SIZE_CMD];
	ssize_t bytes = recv(sock, buf, AEM_SMTP_SIZE_CMD, 0);
	if (bytes < 7) return smtp_fail(NULL, clientAddr, 1); // HELO \r\n

	if (!smtp_helo(sock, domain, lenDomain, buf, bytes)) return smtp_fail(NULL, clientAddr, 2);

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
				printf("Terminating: mbedtls_ssl_handshake returned %d\n", ret);
				tlsClose(tls);
				return;
			}
		}

		bytes = recv_aem(0, tls, buf, AEM_SMTP_SIZE_CMD);
		if (bytes == 0) {
			printf("Terminating: Client closed connection after StartTLS (IP: %s; greeting: %.*s)\n", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			tlsClose(tls);
			return;
		} else if (bytes >= 4 && strncasecmp(buf, "QUIT", 4) == 0) {
			printf("Terminating: Client closed connection cleanly after StartTLS (IP: %s; greeting: %.*s)\n", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			smtp_respond(sock, tls, '2', '2', '1');
			tlsClose(tls);
			return;
		} else if (bytes < 4 || (strncasecmp(buf, "EHLO", 4) != 0 && strncasecmp(buf, "HELO", 4) != 0)) {
			printf("Terminating: Expected EHLO/HELO after StartTLS, but received: %.*s\n", (int)bytes, buf);
			tlsClose(tls);
			return;
		}

		if (!smtp_shlo(tls, domain, lenDomain)) {
			puts("Terminating: Failed to send greeting following StartTLS");
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
			if (bytes < 1) printf("Terminating: Client closed connection (IP: %s; greeting: %.*s)\n", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			else printf("Terminating: Invalid data received (IP: %s; greeting: %.*s)\n", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			break;
		}

		if (bytes > 10 && strncasecmp(buf, "MAIL FROM:", 10) == 0) {
			lenFrom = smtp_addr(buf + 10, bytes - 10, from);
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

			char newTo[AEM_SMTP_MAX_ADDRSIZE];
			size_t lenNewTo = smtp_addr(buf + 8, bytes - 8, newTo);
			if (lenNewTo < 1) {
				return smtp_fail(tls, clientAddr, 102);
			}

			if (!isAddressOurs(newTo, lenNewTo, domain, lenDomain)) {
				if (!smtp_respond(sock, tls, '5', '5', '0')) {
					return smtp_fail(tls, clientAddr, 103);
				}

				bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
				continue;
			}

			lenNewTo -= (lenDomain + 1);

			for (size_t i = 0; i < lenNewTo; i++) {
				if (isupper(newTo[i])) newTo[i] = tolower(newTo[i]);
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
				free(body);
				return smtp_fail(tls, clientAddr, 150);
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
			if (bytes >= 4 && strncasecmp(buf, "QUIT", 4) == 0) infoByte |= AEM_INFOBYTE_CMD_QUIT;

			body[lenBody] = '\0';
			unfoldHeaders(body, &lenBody);
			decodeEncodedWord(body, &lenBody);
			decodeMessage(&body, &lenBody);
			brotliCompress(&body, &lenBody);

			const int cs = (tls == NULL) ? 0 : mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(tls));
			const uint8_t tlsVersion = getTlsVersion(tls);
			deliverMessage(to, lenTo, from, lenFrom, body, lenBody, clientAddr, cs, tlsVersion, infoByte);

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
