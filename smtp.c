#define AEM_SMTP_SIZE_CMD 512 // RFC5321: min. 512

#define AEM_SMTP_MAX_ADDRSIZE 200
#define AEM_SMTP_MAX_ADDRSIZE_TO 5000 // RFC5321: must accept 100 recipients at minimum
#define AEM_SMTP_TIMEOUT 30

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

#define _GNU_SOURCE // for strcasestr

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>
#include <maxminddb.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "Includes/Base64.h"
#include "Includes/Brotli.h"
#include "Includes/CharToInt64.h"
#include "Includes/QuotedPrintable.h"
#include "Includes/SixBit.h"

#include "Database.h"
#include "Message.h"

#include "smtp.h"

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

static int16_t getCountryCode(const struct sockaddr * const sockAddr) {
	if (sockAddr == NULL) return 0;

	MMDB_s mmdb;
	int status = MMDB_open("/GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb);

	if (status != MMDB_SUCCESS) {
		printf("[SMTP.getCountryCode] Can't open database: %s\n", MMDB_strerror(status));
		return 0;
	}

	int mmdb_error;
	MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&mmdb, sockAddr, &mmdb_error);

	if (mmdb_error != MMDB_SUCCESS) {
		printf("[SMTP.getCountryCode] Got an error from libmaxminddb: %s\n", MMDB_strerror(mmdb_error));
		return 0;
	}

	int16_t ret = 0;
	if (result.found_entry) {
		MMDB_entry_data_s entry_data;
		status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);

		if (status == MMDB_SUCCESS) {
			memcpy(&ret, entry_data.utf8_string, 2);
		} else {
			printf("[SMTP.getCountryCode] Error looking up the entry data: %s\n", MMDB_strerror(status));
		}
	} else puts("[SMTP.getCountryCode] No entry for the IP address was found");

	MMDB_close(&mmdb);
	return ret;
}

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

static int send_aem(const int sock, mbedtls_ssl_context * const tls, const char * const data, const size_t lenData) {
	if (data == NULL || lenData < 1) return -1;

	if (tls != NULL) {
		size_t sent = 0;

		while (sent < lenData) {
			int ret;
			do {ret = mbedtls_ssl_write(tls, (unsigned char*)(data + sent), lenData - sent);} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

			if (ret < 0) return ret;

			sent += ret;
		}

		return sent;
	}

	if (sock > 0) return send(sock, data, lenData, 0);

	return -1;
}

static size_t smtp_addr(const char * const buf, const size_t len, char * const addr) {
	if (buf == NULL || len < 1 || addr == NULL) return 0;

	size_t skipBytes = 0;
	while (isspace(buf[skipBytes]) && skipBytes < len) skipBytes++;
	if (skipBytes >= len) return 0;

	if (buf[skipBytes] != '<') return 0;
	skipBytes++;

	size_t lenAddr = 0;
	while (lenAddr < (len - 1) && buf[skipBytes + lenAddr] != '>') lenAddr++;

	if (lenAddr < 1 || lenAddr > AEM_SMTP_MAX_ADDRSIZE) return 0;

	memcpy(addr, buf + skipBytes, lenAddr);
	return lenAddr;
}

static bool smtp_greet(const int sock, const char * const domain, const size_t lenDomain) {
	if (domain == NULL || lenDomain < 1) return false;

	const int lenGreet = 12 + lenDomain;
	char ourGreeting[lenGreet];
	memcpy(ourGreeting, "220 ", 4);
	memcpy(ourGreeting + 4, domain, lenDomain);
	memcpy(ourGreeting + 4 + lenDomain, " ESMTP\r\n", 8);
	return (send(sock, ourGreeting, lenGreet, 0) == lenGreet);
}

static bool smtp_shlo(mbedtls_ssl_context * const tls, const char * const domain, const size_t lenDomain) {
	if (tls == NULL || domain == NULL || lenDomain < 1) return false;

	const ssize_t lenShlo = 4 + lenDomain + AEM_SHLO_RESPONSE_LEN;
	char shlo[lenShlo];
	memcpy(shlo, "250-", 4);
	memcpy(shlo + 4, domain, lenDomain);
	memcpy(shlo + 4 + lenDomain, AEM_SHLO_RESPONSE, AEM_SHLO_RESPONSE_LEN);
	return (send_aem(0, tls, shlo, lenShlo) == lenShlo);
}

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

static void smtp_fail(const struct sockaddr_in * const clientAddr, const int code) {
	printf("[SMTP] Error receiving message (Code: %d, IP: %s)\n", code, inet_ntoa(clientAddr->sin_addr));
}

static void tlsFree(mbedtls_ssl_context * const tls, mbedtls_ssl_config * const conf, mbedtls_ctr_drbg_context * const ctr_drbg, mbedtls_entropy_context * const entropy) {
	if (tls == NULL) return;
	mbedtls_ssl_free(tls);
	mbedtls_ssl_config_free(conf);
	mbedtls_ctr_drbg_free(ctr_drbg);
	mbedtls_entropy_free(entropy);
}

static void deliverMessage(const char * const to, const size_t lenToTotal, const char * const from, const size_t lenFrom, const char * const msgBody, const size_t lenMsgBody,
const struct sockaddr_in * const sockAddr, const int cs, const uint8_t tlsVersion, const unsigned char infoByte, const unsigned char * const addrKey) {
	if (to == NULL || lenToTotal < 1 || from == NULL || lenFrom < 1 || msgBody == NULL || lenMsgBody < 1 || sockAddr == NULL || addrKey == NULL) return;

	const char *toStart = to;
	const char * const toEnd = to + lenToTotal;

	while(1) {
		char * const nextTo = memchr(toStart, '\n', toEnd - toStart);
		const size_t lenTo = ((nextTo != NULL) ? nextTo : toEnd) - toStart;
		if (lenTo < 1) break;

		unsigned char binTo[18];
		int ret = addr2bin(toStart, lenTo, binTo);
		if (ret < 1) {
			puts("[SMTP] Failed to deliver email: addr2bin failed");
			if (nextTo == NULL) return;
			toStart = nextTo + 1;
			continue;
		}

		unsigned char pk[crypto_box_PUBLICKEYBYTES];
		unsigned char flags;
		ret = getPublicKeyFromAddress(binTo, pk, addrKey, &flags);
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

		if (flags & AEM_FLAGS_ADDR_USE_GK && isBlockedByGatekeeper(&geoId, domain, lenDomain, from, lenFrom, charToInt64(pk), addrKey)) return;

		size_t bodyLen = lenMsgBody;
		unsigned char * const boxSet = makeMsg_Ext(pk, binTo, msgBody, &bodyLen, sockAddr->sin_addr.s_addr, cs, tlsVersion, geoId, attach, infoByte, spamByte);
		const size_t bsLen = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + bodyLen + crypto_box_SEALBYTES;

		if (boxSet == NULL) {
			puts("[SMTP]: Failed to deliver email: makeMsg_Ext failed");
			toStart = nextTo + 1;
			continue;
		}

		ret = addUserMessage(charToInt64(pk), boxSet, bsLen);
		free(boxSet);
		if (ret != 0) puts("[SMTP] Failed to deliver email: addUserMessage failed");

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
		const char * const charsetEnd = memchr(ew + 2, '?', (data + *lenData) - (ew + 2));
		if (charsetEnd == NULL) return;
		if (charsetEnd[2] != '?') return;
		const char type = charsetEnd[1];
		memmove(ew, charsetEnd + 3, (data + *lenData) - (charsetEnd + 3));
		*lenData -= ((charsetEnd + 3) - ew);

		const char * const ewEnd = memmem(ew, (data + *lenData) - ew, "?=", 2);
		if (ewEnd == NULL) break;

		size_t lenEw = ewEnd - ew;
		const size_t lenEwOld = lenEw;

		while(1) {
			char * const underscore = memchr(ew, '_', lenEw);
			if (underscore == NULL) break;
			*underscore = ' ';
		}

		if (type == 'Q' || type == 'q') {decodeQuotedPrintable(ew, &lenEw);}
		else if (type == 'B' || type == 'b') {
			unsigned char * const dec = b64Decode((unsigned char*)ew, lenEw, &lenEw);
			if (dec != NULL) {
				memcpy(ew, dec, lenEw);
				free(dec);
			}
		} else return;

		memmove(ew + lenEw, ew + lenEwOld + 2, (data + *lenData) - (ew + lenEwOld + 2));
		*lenData -= (lenEwOld - lenEw + 2);
		data[*lenData] = '\0';
	}
}

static bool isAddressAem(const char * const c, const size_t len) {
	if (c == NULL || len < 1) return false;

	if (len <= 24) {
		for (size_t i = 0; i < len; i++) {
			if (!isalnum(c[i]) && c[i] != '.' && c[i] != '-') return false;
		}
	} else if (len == 36) {
		for (size_t i = 0; i < len; i++) {
			bool ok = false;

			for (int j = 0; j < 16; j++) {
				if (c[i] == AEM_ADDRESS_HEXCHARS[j]) {ok = true; break;}
			}

			if (!ok) return false;
		}
	} else return false;

	return true;
}

static bool isAddressOurs(const char * const addr, const size_t lenAddr, const char * const domain, const size_t lenDomain) {
	if (addr == NULL || lenAddr < 1 || domain == NULL || lenDomain < 1) return false;

	return (
	   lenAddr > (lenDomain + 1)
	&& addr[lenAddr - lenDomain - 1] == '@'
	&& strncasecmp(addr + lenAddr - lenDomain, domain, lenDomain) == 0
	&& isAddressAem(addr, lenAddr - lenDomain - 1)
	);
}

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

void unfoldHeaders(char * const data, size_t * const lenData) {
	const char * const headersEnd = memmem(data, *lenData, "\r\n\r\n", 4);
	if (headersEnd == NULL) return;
	size_t lenHeaders = headersEnd - data;

	while(1) {
		char *crlfWsp = memmem(data, lenHeaders, "\r\n ", 3);
		if (crlfWsp == NULL) crlfWsp = memmem(data, lenHeaders, "\r\n\t", 3);
		if (crlfWsp == NULL) break;

		memmove(crlfWsp, crlfWsp + 2, (data + *lenData) - (crlfWsp + 2));

		*lenData -= 2;
		lenHeaders -= 2;
		data[*lenData] = '\0';
	}
}

void respond_smtp(int sock, mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey, const unsigned char * const addrKey, const char * const domain, const size_t lenDomain, const struct sockaddr_in * const clientAddr) {
	if (sock < 0 || tlsCert == NULL || tlsKey == NULL || addrKey == NULL || domain == NULL || lenDomain < 1 || clientAddr == NULL) return;

	if (!smtp_greet(sock, domain, lenDomain)) return smtp_fail(clientAddr, 0);

	char buf[AEM_SMTP_SIZE_CMD];
	ssize_t bytes = recv(sock, buf, AEM_SMTP_SIZE_CMD, 0);

	if (!smtp_helo(sock, domain, lenDomain, buf, bytes)) return smtp_fail(clientAddr, 1);

	uint8_t infoByte = 0;
	if (buf[0] == 'E') infoByte |= AEM_INFOBYTE_ESMTP;
	const size_t lenGreeting = bytes - 7;
	char greeting[lenGreeting];
	memcpy(greeting, buf + 5, lenGreeting);

	bytes = recv(sock, buf, AEM_SMTP_SIZE_CMD, 0);

	mbedtls_ssl_context *tls = NULL;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	if (bytes >= 8 && strncasecmp(buf, "STARTTLS", 8) == 0) {
		send(sock, "220 aem\r\n", 9, 0);
		tls = &ssl;

		mbedtls_ssl_init(tls);
		mbedtls_ssl_config_init(&conf);
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_init(&ctr_drbg);

		int ret;
		if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
			printf("[SMTP] Terminating: mbedtls_ssl_config_defaults returned %d\n", ret);
			mbedtls_ssl_free(tls);
			mbedtls_ssl_config_free(&conf);
			return;
		}

		mbedtls_ssl_conf_arc4_support(&conf, MBEDTLS_SSL_ARC4_ENABLED);
		mbedtls_ssl_conf_ciphersuites(&conf, smtp_ciphersuites);
		mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1); // Require TLS v1.0+
		mbedtls_ssl_conf_read_timeout(&conf, AEM_SMTP_TIMEOUT);
		mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

		if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char*)"All-Ears Mail SMTP", 18)) != 0) {
			printf("[SMTP] Terminating: mbedtls_ctr_drbg_seed returned %d\n", ret);
			tlsFree(tls, &conf, &ctr_drbg, &entropy);
			return;
		}

		mbedtls_ssl_conf_ca_chain(&conf, tlsCert->next, NULL);
		if ((ret = mbedtls_ssl_conf_own_cert(&conf, tlsCert, tlsKey)) != 0) {
			printf("[SMTP] Terminating: mbedtls_ssl_conf_own_cert returned %d\n", ret);
			tlsFree(tls, &conf, &ctr_drbg, &entropy);
			return;
		}

		if ((ret = mbedtls_ssl_setup(tls, &conf)) != 0) {
			printf("[SMTP] Terminating: mbedtls_ssl_setup returned %d\n", ret);
			tlsFree(tls, &conf, &ctr_drbg, &entropy);
			return;
		}

		mbedtls_ssl_set_bio(tls, &sock, mbedtls_net_send, mbedtls_net_recv, NULL);

		// Handshake
		while ((ret = mbedtls_ssl_handshake(tls)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				printf("[SMTP] Terminating: mbedtls_ssl_handshake returned %d\n", ret);
				tlsFree(tls, &conf, &ctr_drbg, &entropy);
				return;
			}
		}

		bytes = recv_aem(0, tls, buf, AEM_SMTP_SIZE_CMD);
		if (bytes == 0) {
			printf("[SMTP] Terminating: Client closed connection after StartTLS (IP: %s; greeting: %.*s)\n", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			tlsFree(tls, &conf, &ctr_drbg, &entropy);
			return;
		} else if (bytes >= 4 && strncasecmp(buf, "QUIT", 4) == 0) {
			printf("[SMTP] Terminating: Client closed connection cleanly after StartTLS (IP: %s; greeting: %.*s)\n", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			send_aem(sock, tls, "221 aem\r\n", 9);
			tlsFree(tls, &conf, &ctr_drbg, &entropy);
			return;
		} else if (bytes < 4 || (strncasecmp(buf, "EHLO", 4) != 0 && strncasecmp(buf, "HELO", 4) != 0)) {
			printf("[SMTP] Terminating: Expected EHLO/HELO after StartTLS, but received: %.*s\n", (int)bytes, buf);
			tlsFree(tls, &conf, &ctr_drbg, &entropy);
			return;
		}

		if (!smtp_shlo(tls, domain, lenDomain)) {
			puts("[SMTP] Terminating: Failed to send greeting following StartTLS");
			tlsFree(tls, &conf, &ctr_drbg, &entropy);
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
			if (bytes < 1) printf("[SMTP] Terminating: client closed connection (IP: %s; greeting: %.*s)\n", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			else printf("[SMTP] Terminating: invalid data received (IP: %s; greeting: %.*s)\n", inet_ntoa(clientAddr->sin_addr), (int)lenGreeting, greeting);
			break;
		}

		if (bytes > 10 && strncasecmp(buf, "MAIL FROM:", 10) == 0) {
			lenFrom = smtp_addr(buf + 10, bytes - 10, from);
			if (lenFrom < 1) {
				tlsFree(tls, &conf, &ctr_drbg, &entropy);
				return smtp_fail(clientAddr, 100);
			}
		}

		else if (bytes > 8 && strncasecmp(buf, "RCPT TO:", 8) == 0) {
			if (lenFrom < 1) {
				infoByte |= AEM_INFOBYTE_PROTOERR;

				if (send_aem(sock, tls, "503 aem\r\n", 9) != 9) {
					tlsFree(tls, &conf, &ctr_drbg, &entropy);
					return smtp_fail(clientAddr, 101);
				}

				continue;
			}

			char newTo[AEM_SMTP_MAX_ADDRSIZE];
			size_t lenNewTo = smtp_addr(buf + 8, bytes - 8, newTo);
			if (lenNewTo < 1) {
				tlsFree(tls, &conf, &ctr_drbg, &entropy);
				return smtp_fail(clientAddr, 102);
			}

			if (!isAddressOurs(newTo, lenNewTo, domain, lenDomain)) {
				if (send_aem(sock, tls, "550 aem\r\n", 9) != 9) {
					tlsFree(tls, &conf, &ctr_drbg, &entropy);
					return smtp_fail(clientAddr, 103);
				}

				continue;
			}

			lenNewTo -= (lenDomain + 1);

			for (size_t i = 0; i < lenNewTo; i++) {
				if (isupper(newTo[i])) newTo[i] = tolower(newTo[i]);
			}

			if ((lenTo + 1 + lenNewTo) > AEM_SMTP_MAX_ADDRSIZE_TO) {
				if (send_aem(sock, tls, "452 aem\r\n", 9) != 9) { // Too many recipients
					tlsFree(tls, &conf, &ctr_drbg, &entropy);
					return smtp_fail(clientAddr, 104);
				}

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

			if (send_aem(sock, tls, "252 aem\r\n", 9) != 9) { // 252 = Cannot VRFY user, but will accept message and attempt delivery
				tlsFree(tls, &conf, &ctr_drbg, &entropy);
				return smtp_fail(clientAddr, 105);
			}

			continue;
		}

		else if (strncasecmp(buf, "QUIT", 4) == 0) {
			send_aem(sock, tls, "221 aem\r\n", 9);
			break;
		}

		else if (strncasecmp(buf, "DATA", 4) == 0) {
			if (lenFrom < 1 || lenTo < 1) {
				infoByte |= AEM_INFOBYTE_PROTOERR;

				if (send_aem(sock, tls, "503 aem\r\n", 9) != 9) {
					tlsFree(tls, &conf, &ctr_drbg, &entropy);
					return smtp_fail(clientAddr, 106);
				}

				continue;
			}

			if (send_aem(sock, tls, "354 aem\r\n", 9) != 9) {
				tlsFree(tls, &conf, &ctr_drbg, &entropy);
				return smtp_fail(clientAddr, 107);
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

			if (send_aem(sock, tls, "250 aem\r\n", 9) != 9) {
				tlsFree(tls, &conf, &ctr_drbg, &entropy);
				return smtp_fail(clientAddr, 150);
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
			if (bytes >= 4 && strncasecmp(buf, "QUIT", 4) == 0) infoByte |= AEM_INFOBYTE_CMD_QUIT;

			body[lenBody] = '\0';
			unfoldHeaders(body, &lenBody);
			decodeEncodedWord(body, &lenBody);
			brotliCompress(&body, &lenBody);

			const int cs = (tls == NULL) ? 0 : mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(tls));
			const uint8_t tlsVersion = getTlsVersion(tls);
			deliverMessage(to, lenTo, from, lenFrom, body, lenBody, clientAddr, cs, tlsVersion, infoByte, addrKey);

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
			if (send_aem(sock, tls, "500 aem\r\n", 9) != 9) {
				tlsFree(tls, &conf, &ctr_drbg, &entropy);
				return smtp_fail(clientAddr, 108);
			}

			bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
			continue;
		}

		if (send_aem(sock, tls, "250 aem\r\n", 9) != 9) {
			tlsFree(tls, &conf, &ctr_drbg, &entropy);
			return smtp_fail(clientAddr, 150);
		}

		bytes = recv_aem(sock, tls, buf, AEM_SMTP_SIZE_CMD);
	}

	tlsFree(tls, &conf, &ctr_drbg, &entropy);
}
