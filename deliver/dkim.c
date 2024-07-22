#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>

#include "../Common/memeq.h"
#include "../IntCom/Client.h"

#include "dkim.h"

static char getValuePair_dns(const char * const src, size_t * const offset, char * const result, size_t * const lenResult) {
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

static char getValuePair_header(const char * const src, size_t * const offset, char * const result, size_t * const lenResult) {
	if (memeq_anycase(src, "bh=", 3)) {
		const char * const end = strchr(src + 3, ';');
		if (end == NULL) return 0; // TODO
		*offset = end - src;
		*lenResult = *offset - 3;
		memcpy(result, src + 3, *lenResult);
		return 'H';
	}

	const char t = tolower(src[0]);
	if (t == '\0') return 0;
	if (src[1] != '=') return 0;

	const char *end = strchr(src + 2, ';');
	const char *end2 = strchr(src + 2, '\n');

	while (end2 != NULL && isspace(end2[1])) end2 = strchr(end2 + 1, '\n');

	if (end2 != NULL && (end == NULL || end2 < end)) end = end2;
	else if (end == NULL) return 0;

	*offset = end - src;
	*lenResult = *offset - 2;
	memcpy(result, src + 2, *lenResult);

	return t;
}

static int getDkimRecord(struct emailInfo * const email, const char * const selector, unsigned char * const pkBin, size_t * const lenPkBin) {
	if (selector == NULL || selector[0] == '\0' || email->dkim[email->dkimCount].lenDomain < 1) {syslog(LOG_WARNING, "getDkimRecord: Bad input"); return -1;}

	unsigned char tmp[512];
	sprintf((char*)tmp, "%s/%.*s", selector, (int)email->dkim[email->dkimCount].lenDomain, email->dkim[email->dkimCount].domain);

	unsigned char *dkim = NULL;
	int32_t lenDkim = intcom(AEM_INTCOM_SERVER_ENQ, AEM_ENQUIRY_DKIM, tmp, strlen((char*)tmp), &dkim, 0);
	if (lenDkim < 1) {syslog(LOG_WARNING, "DKIM: Enquiry request failed"); return AEM_INTCOM_RESPONSE_ERR;}
	lenDkim--;
	dkim[lenDkim] = '\0';

	int retval = -1;
	size_t offset = 0;
	for(;;) {
		size_t o, lenVal;
		char val[1024];
		const unsigned char key = getValuePair_dns((char*)dkim + offset, &o, val, &lenVal);
		if (key == 0) break;

		offset += o;
		if (dkim[offset] == ';') offset++;
		while (isspace(dkim[offset])) offset++;

		if (lenVal < 1) continue;

		switch (key) {
			case 'v': { // Version: DKIM1
				if (lenVal != 5 || !memeq(val, "DKIM1", 5)) {free(dkim); return -1;}
			break;}

			case 'p': { // Public key
				if (lenVal > 1024) {free(dkim); return -1;}
				if (sodium_base642bin(pkBin, 1024, val, lenVal, " \t\r\n", lenPkBin, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {free(dkim); return -1;}
				retval = 0;
			break;}

			case 't': { // Flags
				if      (lenVal >= 1 && val[0] == 's') {email->dkim[email->dkimCount].dnsFlag_s = true;}
				else if (lenVal >= 1 && val[0] == 'y') {email->dkim[email->dkimCount].dnsFlag_y = true;}

				if (lenVal >= 3 && val[1] == ':') {
					if      (val[2] == 's') {email->dkim[email->dkimCount].dnsFlag_s = true;}
					else if (val[2] == 'y') {email->dkim[email->dkimCount].dnsFlag_y = true;}
				}
			break;}

			default: break; // Ignore others
		}
	}

	free(dkim);
	return retval;
}

static void copyRelaxed(unsigned char * const target, size_t * const lenTarget, const unsigned char * const source, const size_t lenSource) {
	for (size_t i = 0; i < lenSource; i++) {
		// Unfold
		if (lenSource - i > 2 && source[i] == '\r' && source[i + 1] == '\n' && (source[i + 2] == ' ' || source[i + 2] == '\t')) {
			target[*lenTarget] = ' ';
			(*lenTarget)++;
			i += 2;
			continue;
		}

		// Remove whitespace at line ends
		if ((source[i] == ' ' || source[i] == '\t') && isspace(source[i + 1])) continue;

		// Compact multiple tabs/spaces into one space
		if (*lenTarget > 0 && (target[*lenTarget - 1] == ' ' || target[*lenTarget - 1] == '\t') && (source[i] == ' ' || source[i] == '\t')) {
			target[*lenTarget - 1] = ' ';
			continue;
		}

		if (source[i] == '\t')
			target[*lenTarget] = ' ';
		else
			target[*lenTarget] = source[i];

		(*lenTarget)++;
	}
}

static bool verifyDkimSig(struct emailInfo * const email, RsaKey * const pk, const unsigned char * const dkimSignature, const size_t lenDkimSignature, char * const copyHeaders, const unsigned char * const headersSource, const size_t lenHeaders, const unsigned char * const dkimHeader, const size_t lenDkimHeader, bool * const headSimple) {
	char headers[lenHeaders + 1];
	memcpy(headers, headersSource, lenHeaders);
	headers[lenHeaders] = '\0';

	size_t lenSimple = 0;
	unsigned char simple[lenHeaders + lenDkimHeader];

	size_t lenRelaxed = 0;
	unsigned char relaxed[lenHeaders + lenDkimHeader + 2];

	char *h = strtok(copyHeaders, ":");
	while (h != NULL) {
		while (isspace(*h)) h++;
		const size_t lenH = strlen(h);

		if      (memeq_anycase(h, "Date", 4))        email->dkim[email->dkimCount].sgnDate    = true;
		else if (memeq_anycase(h, "From", 4))        email->dkim[email->dkimCount].sgnFrom    = true;
		else if (memeq_anycase(h, "Message-ID", 10)) email->dkim[email->dkimCount].sgnMsgId   = true;
		else if (memeq_anycase(h, "Reply-To", 8))    email->dkim[email->dkimCount].sgnReplyTo = true;
		else if (memeq_anycase(h, "Subject", 7))     email->dkim[email->dkimCount].sgnSubject = true;
		else if (memeq_anycase(h, "To", 2))          email->dkim[email->dkimCount].sgnTo      = true;

		unsigned char *s = (unsigned char*)strcasestr(headers, h);

		while (s != NULL && (((const char*)s != headers && *(s - 1) != '\n') || s[lenH] != ':')) {
			s = (unsigned char*)strcasestr((char*)s + lenH, h);
		}

		if (s == NULL) {
			// Header not present
			h = strtok(NULL, ":");
			continue;
		}

		const unsigned char *end = s + lenH + 1; // Skip name and colon
		bool found = false;
		for(;;) {
			if (*end == '\0') break;

			if (memeq(end, "\r\n", 2) && end[2] != ' ' && end[2] != '\t') {
				found = true;
				break;
			}

			end++;
		}

		if (!found) end = (unsigned char*)headers + lenHeaders;

		memcpy(simple + lenSimple, s, end - s);
		lenSimple += end - s;

		memcpy(simple + lenSimple, "\r\n", 2);
		lenSimple += 2;

		// Relaxed
		const unsigned char *s2 = s + lenH + 1; // Skip name and colon
		while (s2 < end) {if (isspace(*s2)) s2++; else break;}

		for (size_t i = 0; i < lenH; i++) {
			relaxed[lenRelaxed++] = tolower(h[i]);
		}

		relaxed[lenRelaxed++] = ':';
		copyRelaxed(relaxed, &lenRelaxed, s2, end - s2);
		memcpy(relaxed + lenRelaxed, "\r\n", 2);
		lenRelaxed += 2;

		memset(s, '.', end - s);
		h = strtok(NULL, ":");
	}
	memcpy(simple + lenSimple, dkimHeader, lenDkimHeader);
	lenSimple += lenDkimHeader;

	// Verify sig
	unsigned char dkim_hash[crypto_hash_sha256_BYTES];
	if (crypto_hash_sha256(dkim_hash, simple, lenSimple) == 0) {
		unsigned char o[1024];
		bzero(o, 1024);

		if (wc_RsaSSL_Verify(dkimSignature, lenDkimSignature, o, 1024, pk) >= 51 && memeq(o + 19, dkim_hash, crypto_hash_sha256_BYTES)) {
			*headSimple = true;
			return true;
		}
	}

	memcpy(relaxed + lenRelaxed, "dkim-signature:", 15);
	lenRelaxed += 15;
	size_t dkimOffset = 15;
	while (isspace(dkimHeader[dkimOffset])) dkimOffset++;
	size_t addLen = 0;

	copyRelaxed(relaxed + lenRelaxed, &addLen, dkimHeader + dkimOffset, lenDkimHeader - dkimOffset);
	lenRelaxed += addLen;

	if (crypto_hash_sha256(dkim_hash, relaxed, lenRelaxed) == 0) {
		unsigned char o[1024];
		bzero(o, 1024);

		if (wc_RsaSSL_Verify(dkimSignature, lenDkimSignature, o, 1024, pk) >= 51 && memeq(o + 19, dkim_hash, crypto_hash_sha256_BYTES)) {
			*headSimple = true;
			return true;
		}
	}

	email->dkimFailed = true;
	return false;
}

int verifyDkim(struct emailInfo * const email, const unsigned char * const src, const size_t lenSrc) {
	const unsigned char *headEnd = memmem(src, lenSrc, "\r\n\r\n", 4);
	if (headEnd == NULL) {syslog(LOG_WARNING, "DKIM: No headers-end found"); return 0;}
	headEnd += 4;
	const size_t lenHead = headEnd - src;

	const unsigned char *dkimHeader = src;
	if (!memeq_anycase(dkimHeader, "DKIM-Signature:", 15)) {syslog(LOG_WARNING, "DKIM: Signature not at beginning"); return 0;}
	size_t offset = 15;

	while (isspace(dkimHeader[offset])) offset++;

	size_t lenDkimSignature = 0;
	unsigned char dkim_signature[1024]; // 8k
	unsigned char dkim_bodyhash[crypto_hash_sha256_BYTES];

	email->dkim[email->dkimCount].algoRsa = true;
	email->dkim[email->dkimCount].algoSha256 = true;

	size_t lenBody = lenSrc - lenHead;
	size_t lenTrunc = 0;

	size_t lenUserId = 0;
	char userId[256];

	char copyHeaders[1024];
	char dkim_selector[256];
	bzero(dkim_selector, 256);

	size_t sigPos = 0;
	size_t sigLen = 0;
	bool delSig = false;

	for(;;) {
		size_t o, lenVal;
		char val[1024];
		const char key = getValuePair_header((const char*)dkimHeader + offset, &o, val, &lenVal);
		if (key == 0) break;

		if (offset + o > lenHead) break;
		offset += o;
		size_t startOffset = offset - lenVal;

		if (dkimHeader[offset] == ';') offset++;
		while (isspace(dkimHeader[offset])) offset++;

		if (lenVal < 1) continue;

		switch (key) {
			case 'v': { // Version
				if (lenVal != 1 || *val != '1') {
					syslog(LOG_WARNING, "Unsupported DKIM version: %.*s", (int)lenVal, val);
					delSig = true;
				}
			break;}

			case 'a': { // Algo
				// TODO: EdDSA, RSA-SHA support
				if (lenVal != 10 || !memeq_anycase(val, "rsa-sha256", 10)) {
					syslog(LOG_WARNING, "Unsupported DKIM algorithm: %.*s", (int)lenVal, val);
					delSig = true;
				}
			break;}

			case 'd': { // Domain
				if (lenVal > 67) {
					syslog(LOG_WARNING, "Excessive DKIM D-field size: %zu", lenVal);
					delSig = true;
				} else {
					memcpy(email->dkim[email->dkimCount].domain, val, lenVal);
					email->dkim[email->dkimCount].lenDomain = lenVal;
				}
			break;}

			case 's': { // Selector
				if (lenVal > 255) {
					syslog(LOG_WARNING, "Excessive DKIM S-field size: %zu", lenVal);
					delSig = true;
				} else {
					memcpy(dkim_selector, val, lenVal);
					dkim_selector[lenVal] = '\0';
				}
			break;}

			case 'c': break; // Canon. method; ignored

			case 'l': { // Length of body
				char tmp[lenVal + 1];
				memcpy(tmp, val, lenVal);
				tmp[lenVal] = '\0';
				int newLen = strtol(tmp, NULL, 10);
				if (newLen >= 0 && newLen < (int)lenBody) lenTrunc = newLen;
			break;}

			case 'q': { // Query method
				if (lenVal != 7 || !memeq_anycase(val, "dns/txt", 7)) {
					syslog(LOG_WARNING, "Non-DNS query method: %.*s", (int)lenVal, val);
					delSig = true;
				}
			break;}

			case 't': { // Timestamp
				if (*val == '-') break;
				char tmp[lenVal + 1];
				memcpy(tmp, val, lenVal);
				tmp[lenVal] = '\0';
				email->dkim[email->dkimCount].ts_sign = strtoul(tmp, NULL, 10);
				if (email->dkim[email->dkimCount].ts_sign < 1609459200) email->dkim[email->dkimCount].ts_sign = 0; // 2021-01-01
				// TODO: reject future timestamps
			break;}

			case 'i': { // Identifier
				if (lenVal > 255) {
					syslog(LOG_WARNING, "Excessive DKIM I-field size: %zu", lenVal);
					delSig = true;
				} else {
					memcpy(userId, val, lenVal);
					lenUserId = lenVal;
				}
			break;}

			case 'x': { // Expiry
				if (*val == '-') break;
				char tmp[lenVal + 1];
				memcpy(tmp, val, lenVal);
				tmp[lenVal] = '\0';
				email->dkim[email->dkimCount].ts_expr = strtoul(tmp, NULL, 10);
				if (email->dkim[email->dkimCount].ts_expr < 1609459200) email->dkim[email->dkimCount].ts_expr = 0; // 2021-01-01
			break;}

			case 'h': { // Headers signed
				if (lenVal > 1023) {
					syslog(LOG_WARNING, "Excessive DKIM H-field size: %zu", lenVal);
					delSig = true;
				} else {
					memcpy(copyHeaders, val, lenVal);
					copyHeaders[lenVal] = '\0';
				}
			break;}

			case 'H': { // bodyhash
				if (sodium_base642bin(dkim_bodyhash, crypto_hash_sha256_BYTES, val, lenVal, " \t\r\n", NULL, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
					syslog(LOG_WARNING, "Invalid DKIM bodyhash");
					delSig = true;
				}
			break;}

			case 'b': { // Signature
				sigPos = startOffset;
				sigLen = lenVal;
				if (sodium_base642bin(dkim_signature, 1024, val, lenVal, " \t\r\n", &lenDkimSignature, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
					delSig = true;
				}
			break;}

			default: syslog(LOG_WARNING, "Unsupported DKIM param: %c", key);
		}
	}

	if (delSig || offset < 10 || offset > 2047 || sigPos == 0 || sigLen == 0) return offset;

	unsigned char dh[2048];
	memcpy(dh, dkimHeader, offset);
	size_t lenDh = offset;
	const size_t copyLen = (dh + offset) - (dh + sigPos + sigLen);
	if (copyLen > 0) memmove(dh + sigPos, dh + sigPos + sigLen, copyLen);
	lenDh -= sigLen;
	if (dh[lenDh - 1] == '\n') lenDh--;
	if (dh[lenDh - 1] == '\r') lenDh--;
	dh[lenDh] = '\0';

	if (lenUserId > 0 && (
	   (lenUserId == email->lenEnvFr && memeq(email->envFr, userId, lenUserId))
	|| (lenUserId == email->lenHdrFr && memeq(email->hdrFr, userId, lenUserId))
	|| (lenUserId == email->lenHdrRt && memeq(email->hdrRt, userId, lenUserId))
	) && (memeq(userId + lenUserId - email->dkim[email->dkimCount].lenDomain, email->dkim[email->dkimCount].domain, email->dkim[email->dkimCount].lenDomain)))
		email->dkim[email->dkimCount].fullId = true;

	size_t lenPkBin;
	unsigned char pkBin[1024];
	if (getDkimRecord(email, dkim_selector, pkBin, &lenPkBin) != 0) {
		syslog(LOG_WARNING, "getDkimRecord failed");
		email->dkimFailed = true;
		return offset;
	}

	// Verify bodyhash
	// Remove extra linebreaks at end
	while (lenBody > 4 && memeq(headEnd + lenBody - 4, "\r\n\r\n", 4)) lenBody -= 2;
	if (lenTrunc > lenBody) lenTrunc = 0;

	unsigned char calc_bodyhash[crypto_hash_sha256_BYTES];
	if (crypto_hash_sha256(calc_bodyhash, headEnd, (lenTrunc > 0) ? lenTrunc : lenBody) != 0) {
		email->dkimFailed = true;
		return offset;
	}

	if (!memeq(calc_bodyhash, dkim_bodyhash, crypto_hash_sha256_BYTES)) {
		// Simple failed, try Relaxed
		unsigned char relaxed[lenBody];
		size_t lenRelaxed = 0;
		for (size_t i = 0; i < lenBody; i++) {
			if ((headEnd[i] == ' ' || headEnd[i] == '\t') && isspace(headEnd[i + 1])) continue; // Remove whitespace at line ends; compact multiple WSP to one SP

			if (i > 0 && (headEnd[i - 1] == ' ' || headEnd[i - 1] == '\t') && headEnd[i] == '\t') {
				relaxed[lenRelaxed] = ' ';
				lenRelaxed++;
				continue;
			}

			if (headEnd[i] == '\t')
				relaxed[lenRelaxed] = ' ';
			else
				relaxed[lenRelaxed] = headEnd[i];

			lenRelaxed++;
		}

		if (lenTrunc > lenRelaxed) lenTrunc = 0;

		if (crypto_hash_sha256(calc_bodyhash, relaxed, (lenTrunc > 0) ? lenTrunc : lenRelaxed) != 0) {
			email->dkimFailed = true;
			return offset;
		}

		if (!memeq(calc_bodyhash, dkim_bodyhash, crypto_hash_sha256_BYTES)) {
			email->dkimFailed = true;
			return offset;
		}

		email->dkim[email->dkimCount].bodySimple = false;
	} else email->dkim[email->dkimCount].bodySimple = true;

	RsaKey pk;
	if (wc_InitRsaKey(&pk, NULL) != 0) {syslog(LOG_ERR, "wc_InitRsaKey failed"); return offset;}
	word32 idx = 0;
	const int ret = wc_RsaPublicKeyDecode(pkBin, &idx, &pk, lenPkBin);
	if (ret != 0) {
		syslog(LOG_INFO, "Failed decoding public key: %d [%zd]\n", ret, lenPkBin);
		wc_FreeRsaKey(&pk);
		email->dkimFailed = true;
		return offset;
	}

	if (verifyDkimSig(email, &pk, dkim_signature, lenDkimSignature, copyHeaders, dkimHeader + offset, headEnd - dkimHeader - offset - 4, dh, lenDh, &email->dkim[email->dkimCount].headSimple)) {
		if (lenTrunc > 0) email->dkim[email->dkimCount].bodyTrunc = true;
		(email->dkimCount)++;
	}

	wc_FreeRsaKey(&pk);
	return offset;
}
