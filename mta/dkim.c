#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <mbedtls/x509.h> // For RSA
#include <sodium.h>

#include "../Common/UnixSocketClient.h"

#include "dkim.h"

char getValuePair(const char * const src, size_t * const offset, char * const result, size_t * const lenResult) {
	if (strncasecmp(src, "bh=", 3) == 0) {
		const char * const end = strpbrk(src + 3, " \t\f\v\r\n;");
		if (end == NULL) return 0;
		*offset = end - src;
		*lenResult = *offset - 3;
		memcpy(result, src + 3, *lenResult);
		return 'H';
	}

	const char t = tolower(src[0]);
	if (t == '\0') return 0;
	if (src[1] != '=') return 0;

	const char *end = strpbrk(src + 2, " \t\f\v\r\n;");
	if (end == NULL) end = src + strlen(src);

	*offset = end - src;
	*lenResult = *offset - 2;
	memcpy(result, src + 2, *lenResult);
	return t;
}

int getDkimRecord(struct emailInfo * const email, const char * const selector, unsigned char * const pkBin, size_t * const lenPkBin) {
	if (selector == NULL || selector[0] == '\0' || email->dkim[0].lenDomain < 1) {syslog(LOG_WARNING, "getDkimRecord: Bad input"); return -1;}

	unsigned char tmp[512];
	sprintf((char*)tmp, "%s/%.*s", selector, (int)email->dkim[0].lenDomain, email->dkim[0].domain);

	const int sock = enquirySocket(AEM_ENQUIRY_DKIM, tmp, strlen((char*)tmp));
	if (sock < 0) {syslog(LOG_ERR, "Failed connecting to Enquiry"); return -1;}

	unsigned char dkim[2048];
	const int lenDkim = recv(sock, dkim, 2047, 0);
	close(sock);
	if (lenDkim < 1) {syslog(LOG_ERR, "Failed communicating with Enquiry"); return -1;}
	dkim[lenDkim] = 0;

	int retval = -1;
	size_t offset = 0;
	while(1) {
		size_t o, lenVal;
		char val[1024];
		const unsigned char key = getValuePair((char*)dkim + offset, &o, val, &lenVal);
		if (key == 0) break;

		offset += o;
		if (dkim[offset] == ';') offset++;
		while (isspace(dkim[offset])) offset++;

		if (lenVal < 1) continue;

		switch (key) {
			case 'v': { // Version: DKIM1
				if (lenVal != 5 || memcmp(val, "DKIM1", 5) != 0) return -1;
			break;}

			case 'p': { // Public key
				if (lenVal > 1024) return -1;
				if (sodium_base642bin(pkBin, 1024, val, lenVal, NULL, lenPkBin, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) return -1;
				retval = 0;
			break;}

			case 't': { // Flags
				if      (lenVal >= 1 && val[0] == 's') {email->dkim[0].dnsFlag_s = true;}
				else if (lenVal >= 1 && val[0] == 'y') {email->dkim[0].dnsFlag_y = true;}

				if (lenVal >= 3 && val[1] == ':') {
					if      (val[2] == 's') {email->dkim[0].dnsFlag_s = true;}
					else if (val[2] == 'y') {email->dkim[0].dnsFlag_y = true;}
				}
			break;}

			default: break; // Ignore others
		}
	}

	return retval;
}

void verifyDkim(struct emailInfo * const email, const unsigned char * const src, const size_t lenSrc) {
	const unsigned char *headEnd = memmem(src, lenSrc, "\r\n\r\n", 4);
	if (headEnd == NULL) return;
	headEnd += 4;
	const size_t lenHead = headEnd - src;

	const char *dkimHeader = strcasestr((char*)src, "\nDKIM-Signature:");
	if (dkimHeader == NULL || dkimHeader > (char*)headEnd) return;
	dkimHeader++;
	size_t offset = 15;

	while (isspace(dkimHeader[offset])) offset++;

	unsigned char dkim_signature[1024]; // 8k
	unsigned char dkim_bodyhash[32];

	char dkim_selector[256];
	bzero(dkim_selector, 256);

	int dkim_sign_ts = 0;
	int dkim_expr_ts = 0; // default: no expiry

	email->dkim[0].algoRsa = true;
	email->dkim[0].algoSha256 = true;

	size_t lenBody = email->lenBody;
	size_t finalOff = 0;

	while (finalOff == 0) {
		size_t o, lenVal;
		char val[1024];
		const char key = getValuePair(dkimHeader + offset, &o, val, &lenVal);
		if (key == 0) break;

		if (offset + o > lenHead) break;
		offset += o;
		if (dkimHeader[offset] == ';') offset++;
		while (isspace(dkimHeader[offset])) offset++;

		if (lenVal < 1) continue;

		switch (key) {
			case 'v': { // Version
				if (lenVal != 1 || *val != '1') return;
			break;}

			case 'a': { // Algo
				// TODO: EdDSA, RSA-SHA support
				if (lenVal != 10 || strncmp(val, "rsa-sha256", 10) != 0) return;
			break;}

			case 'd': { // Domain
				if (lenVal > 67) return;
				memcpy(email->dkim[0].domain, val, lenVal);
				email->dkim[0].lenDomain = lenVal;
			break;}

			case 's': { // Selector
				if (lenVal > 255) return;
				memcpy(dkim_selector, val, lenVal);
				dkim_selector[lenVal] = '\0';
			break;}

			case 'c': break; // Canon. method; ignored

			case 'l': { // Length of body
				email->dkim[0].bodyTrunc = true;

				char tmp[lenVal + 1];
				memcpy(tmp, val, lenVal);
				tmp[lenVal] = '\0';
				int newLen = strtol(tmp, NULL, 10);
				if (newLen >= 0 && newLen < (int)lenBody) lenBody = newLen;
			break;}

			case 'q': { // Query method
				if (lenVal != 7 || strncmp(val, "dns/txt", 7) != 0) return;
			break;}

			case 't': { // Timestamp
				char tmp[lenVal + 1];
				memcpy(tmp, val, lenVal);
				tmp[lenVal] = '\0';
				dkim_sign_ts = strtol(tmp, NULL, 10);
				if (dkim_sign_ts < 1609459200) dkim_sign_ts = 0; // 2021-01-01
				// TODO: reject future timestamps
			break;}

			case 'i': { // Identifier
				// TODO: Compare against sender
			break;}

			case 'x': { // Expiry
				char tmp[lenVal + 1];
				memcpy(tmp, val, lenVal);
				tmp[lenVal] = '\0';
				dkim_expr_ts = strtol(tmp, NULL, 10);
				if (dkim_expr_ts < 1609459200) dkim_sign_ts = 0; // 2021-01-01
			break;}

			case 'h': { // Headers signed
				// TODO
			break;}

			case 'H': { // bodyhash
				if (sodium_base642bin(dkim_bodyhash, 32, val, lenVal, NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) return;
			break;}

			case 'b': { // Signature - end
				if (sodium_base642bin(dkim_signature, 1024, val, lenVal, NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) return;
				finalOff = o;
			break;}

			default: syslog(LOG_WARNING, "Unsupported DKIM param: %c", key);
		}
	}

	size_t lenPkBin;
	unsigned char pkBin[1024];
	if (getDkimRecord(email, dkim_selector, pkBin, &lenPkBin) != 0) return;

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	const int ret = mbedtls_pk_parse_public_key(&pk, pkBin, lenPkBin);
	if (ret != 0) {
		syslog(LOG_INFO, "pk_parse failed: %x", -ret);
		mbedtls_pk_free(&pk);
		return;
	}

	// Verify bodyhash
	unsigned char calc_bodyhash[32];
	if (crypto_hash_sha256(calc_bodyhash, headEnd, lenSrc - lenHead) != 0) return;
	if (memcmp(calc_bodyhash, dkim_bodyhash, 32) != 0) return;

	unsigned char x[lenHead];
	const size_t cpLen = (dkimHeader + offset) - dkimHeader - finalOff;
	sprintf((char*)x, "%.*s%.*s", (int)(lenHead - 3 - offset), dkimHeader + offset, (int)cpLen, dkimHeader);

	// Verify sig
	unsigned char dkim_hash[32];
	if (crypto_hash_sha256(dkim_hash, x, strlen((char*)x)) != 0) return;

	if (mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, dkim_hash, 32, dkim_signature, 256) != 0) {
		mbedtls_pk_free(&pk);
		return;
	}

	mbedtls_pk_free(&pk);

	email->dkim[0].sgnAll = true;
	email->dkimCount = 1;
	return;
}
