#include <ctype.h>
#include <errno.h>
#include <math.h>
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
#include <wolfssl/wolfcrypt/ed25519.h>
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

static int getDkimRecord(struct emailInfo * const email, unsigned char * const pkBin, size_t * const lenPkBin) {
	if (email->dkim[email->dkimCount].lenDomain < 1 || email->dkim[email->dkimCount].lenSelector < 1) {syslog(LOG_WARNING, "getDkimRecord: Bad input"); return -1;}

	unsigned char tmp[512];
	const int lenTmp = sprintf((char*)tmp, "%.*s/%.*s", (int)email->dkim[email->dkimCount].lenSelector, email->dkim[email->dkimCount].selector, (int)email->dkim[email->dkimCount].lenDomain, email->dkim[email->dkimCount].domain);

	unsigned char *dkim = NULL;
	int32_t lenDkim = intcom(AEM_INTCOM_SERVER_ENQ, AEM_ENQUIRY_DKIM, tmp, lenTmp, &dkim, 0);
	if (lenDkim < 1) {syslog(LOG_WARNING, "DKIM: Enquiry request failed"); return AEM_INTCOM_RESPONSE_ERR;}
	lenDkim--;
	dkim[lenDkim] = '\0';

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
			case 'g': { // Granularity (address, with wildcard support)
				// TODO
			break;}

			case 'k': { // Key type
				// TODO
			break;}

			case 'h': { // Hash algorithms allowed
				// TODO
			break;}

			case 'n': { // Notes
				if (lenVal >= AEM_DKIM_TEXT_MAXLEN) {
					lenVal = AEM_DKIM_TEXT_MAXLEN;
				}

				email->dkim[email->dkimCount].lenNotes = AEM_DKIM_TEXT_MAXLEN;
				memcpy(email->dkim[email->dkimCount].notes, val, AEM_DKIM_TEXT_MAXLEN);
			break;}

			case 'p': { // Public key
				sodium_base642bin(pkBin, 1024, val, lenVal, " \t\r\n", lenPkBin, NULL, sodium_base64_VARIANT_ORIGINAL);
			break;}

			case 's': { // Service type
				if (! ((lenVal == 1 && *val == '*') || (lenVal == 5 && memeq_anycase(val, "email", lenVal)))) {
					email->dkim[email->dkimCount].notEmail = true;
				}
			break;}

			case 't': { // Flags
				if (lenVal > 0) {
					if (memchr(val, 's', lenVal) != NULL) {email->dkim[email->dkimCount].dnsFlag_s = true;}
					if (memchr(val, 'y', lenVal) != NULL) {email->dkim[email->dkimCount].dnsFlag_y = true;}
				}
			break;}

			case 'v': { // Version: DKIM1
				if (lenVal != 5 || !memeq(val, "DKIM1", 5)) {free(dkim); syslog(LOG_WARNING, "Invalid DKIM version: %.*s", (int)lenVal, val); return -1;}
			break;}

			default: break; // Ignore others
		}
	}

	free(dkim);
	return 0;
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

static void verifyDkimSig(struct emailInfo * const email, RsaKey * const pk, const unsigned char * const dkimSignature, const size_t lenDkimSignature, char * const copyHeaders, const unsigned char * const headersSource, const size_t lenHeaders, const unsigned char * const dkimHeader, const size_t lenDkimHeader, const int lenHash) {
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
		size_t lenH = strlen(h);
		while (lenH > 0) {
			if (isspace(h[lenH - 1])) {
				lenH--;
				h[lenH] = '\0';
			} else break;
		}

		if (lenH < 1) {
			h = strtok(NULL, ":");
			continue;
		}

		     if (memeq_anycase(h, "Content-Type", 12)) email->dkim[email->dkimCount].sgnCt   = true;
		else if (memeq_anycase(h, "Date", 4))          email->dkim[email->dkimCount].sgnDate = true;
		else if (memeq_anycase(h, "From", 4))          email->dkim[email->dkimCount].sgnFrom = true;
		else if (memeq_anycase(h, "Message-ID", 10))   email->dkim[email->dkimCount].sgnId   = true;
		else if (memeq_anycase(h, "MIME-Version", 12)) email->dkim[email->dkimCount].sgnMv   = true;
		else if (memeq_anycase(h, "Reply-To", 8))      email->dkim[email->dkimCount].sgnRt   = true;
		else if (memeq_anycase(h, "Subject", 7))       email->dkim[email->dkimCount].sgnSubj = true;
		else if (memeq_anycase(h, "To", 2))            email->dkim[email->dkimCount].sgnTo   = true;

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
	if (lenHash == 20) {
		wc_ShaHash(simple, lenSimple, dkim_hash);
	} else {
		wc_Sha256Hash(simple, lenSimple, dkim_hash);
	}

	unsigned char o[1024];
	bzero(o, 1024);
	if (wc_RsaSSL_Verify(dkimSignature, lenDkimSignature, o, 1024, pk) >= 19 + lenHash) {
		email->dkim[email->dkimCount].validSig = true;
	}

	if (memeq(o + 19, dkim_hash, lenHash)) {
		email->dkim[email->dkimCount].headHash = AEM_DKIM_HASH_PASS_SIMPLE;
		return;
	}

	// Simple failed, try Relaxed
	memcpy(relaxed + lenRelaxed, "dkim-signature:", 15);
	lenRelaxed += 15;
	size_t dkimOffset = 15;
	while (isspace(dkimHeader[dkimOffset])) dkimOffset++;
	size_t addLen = 0;

	copyRelaxed(relaxed + lenRelaxed, &addLen, dkimHeader + dkimOffset, lenDkimHeader - dkimOffset);
	lenRelaxed += addLen;

	if (lenHash == 20) {
		wc_ShaHash(relaxed, lenRelaxed, dkim_hash);
	} else {
		wc_Sha256Hash(relaxed, lenRelaxed, dkim_hash);
	}

	email->dkim[email->dkimCount].headHash = (memeq(o + 19, dkim_hash, lenHash)) ? AEM_DKIM_HASH_PASS_RELAX : AEM_DKIM_HASH_FAIL;
}

int verifyDkim(struct emailInfo * const email, const unsigned char * const src, const size_t lenSrc, const size_t maxOffset) {
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
	bzero(dkim_signature, 1024);

	unsigned char dkim_bodyhash[crypto_hash_sha256_BYTES];
	bzero(dkim_bodyhash, crypto_hash_sha256_BYTES);

	email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_BAD_SHA1;

	size_t lenBody = lenSrc - lenHead;
	size_t lenTrunc = 0;

	char copyHeaders[1024];

	size_t sigPos = 0;
	size_t sigLen = 0;
	bool delSig = false;

	long long tsSig = 0;
	long long tsExp = 0;

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

		if (offset >= maxOffset) {offset = maxOffset; break;}
		if (lenVal < 1) continue;

		switch (key) {
			case 'v': { // Version
				if (lenVal != 1 || *val != '1') {
					syslog(LOG_WARNING, "Unsupported DKIM version: %.*s", (int)lenVal, val);
					delSig = true;
				}
			break;}

			case 'a': { // Algorithm of signature
				if (lenVal == 14 || memeq_anycase(val, "ed25519-sha256", 14)) {
					email->dkim[email->dkimCount].algo = AEM_DKIM_ED25519_SHA256;
				} else if (lenVal == 10 || memeq_anycase(val, "rsa-sha256", 10)) {
					email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_512_SHA256;
				} else if (lenVal == 8 || memeq_anycase(val, "rsa-sha1", 8)) {
					email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_512_SHA1;
				} else {
					syslog(LOG_WARNING, "Unsupported DKIM algorithm: %.*s", (int)lenVal, val);
					delSig = true;
				}
			break;}

			case 'd': { // Domain
				if (lenVal > AEM_DKIM_TEXT_MAXLEN) {
					syslog(LOG_WARNING, "Excessive DKIM D-field size: %zu", lenVal);
					delSig = true;
				} else {
					memcpy(email->dkim[email->dkimCount].domain, val, lenVal);
					email->dkim[email->dkimCount].lenDomain = lenVal;
				}
			break;}

			case 's': { // Selector
				if (lenVal > AEM_DKIM_TEXT_MAXLEN) {
					syslog(LOG_WARNING, "Excessive DKIM S-field size: %zu", lenVal);
					delSig = true;
				} else {
					memcpy(email->dkim[email->dkimCount].selector, val, lenVal);
					email->dkim[email->dkimCount].lenSelector = lenVal;
				}
			break;}

			case 'c': break; // Canon. method; ignored

			case 'l': { // Length of body
				email->dkim[email->dkimCount].bodyTruncated = true;

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
				if (*val == '-' || lenVal != 10) break;

				char tmp[lenVal + 1];
				memcpy(tmp, val, lenVal);
				tmp[lenVal] = '\0';

				errno = 0;
				tsSig = strtoll(tmp, NULL, 10);
				if (errno == 0) {
					const long long tsDiff = tsSig - llrint((double)(email->binTs + AEM_BINTS_BEGIN) / 1000);
					if (tsDiff != 0) {
						email->dkim[email->dkimCount].ts_sig = MIN(AEM_DKIM_SIGTS_MAX, llabs(tsDiff));
					}
				}
			break;}

			case 'i': { // Identity
				if (lenVal > AEM_DKIM_TEXT_MAXLEN) {
					syslog(LOG_WARNING, "Excessive DKIM I-field size: %zu", lenVal);
					delSig = true;
				} else {
					memcpy(email->dkim[email->dkimCount].identity, val, lenVal);
					email->dkim[email->dkimCount].lenIdentity = lenVal;
				}
			break;}

			case 'x': { // Expiration
				if (*val == '-' || lenVal != 10) break;
				char tmp[lenVal + 1];
				memcpy(tmp, val, lenVal);
				tmp[lenVal] = '\0';
				tsExp = strtoll(tmp, NULL, 10);
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

			case 'H': { // Hash of body
				sodium_base642bin(dkim_bodyhash, crypto_hash_sha256_BYTES, val, lenVal, " \t\r\n", NULL, NULL, sodium_base64_VARIANT_ORIGINAL);
			break;}

			case 'b': { // Signature
				sigPos = startOffset;
				sigLen = lenVal;
				sodium_base642bin(dkim_signature, 1024, val, lenVal, " \t\r\n", &lenDkimSignature, NULL, sodium_base64_VARIANT_ORIGINAL);
			break;}

			case 'z': { // Signature
				email->dkim[email->dkimCount].zUsed = true;
			break;}

			default: syslog(LOG_WARNING, "Unsupported DKIM param: %c", key);
		}
	}

	if (delSig || offset < 10 || offset > 2047 || sigPos == 0 || sigLen == 0) return offset;

	if (tsExp != 0) {
		const long long expDiff = tsExp - ((tsSig > 0) ? tsSig : llrint((double)(email->binTs + AEM_BINTS_BEGIN) / 1000));
		if (expDiff > 0) email->dkim[email->dkimCount].ts_exp = MIN(AEM_DKIM_EXPTS_MAX, expDiff);
	}

	unsigned char dh[2048];
	memcpy(dh, dkimHeader, offset);
	size_t lenDh = offset;
	const size_t copyLen = (dh + offset) - (dh + sigPos + sigLen);
	if (copyLen > 0) memmove(dh + sigPos, dh + sigPos + sigLen, copyLen);
	lenDh -= sigLen;
	if (dh[lenDh - 1] == '\n') lenDh--;
	if (dh[lenDh - 1] == '\r') lenDh--;
	dh[lenDh] = '\0';

	size_t lenPkBin = 0;
	unsigned char pkBin[1024];
	if (getDkimRecord(email, pkBin, &lenPkBin) != 0) {
		syslog(LOG_WARNING, "getDkimRecord failed");
		return offset;
	}

	const int lenHash = (email->dkim[email->dkimCount].algo == AEM_DKIM_RSA_512_SHA1) ? 20 : 32;

	switch (email->dkim[email->dkimCount].algo) {
		case AEM_DKIM_ED25519_SHA256:
			if (lenPkBin != 32/*ed25519*/) email->dkim[email->dkimCount].algo = AEM_DKIM_ED25519_BAD_SHA256;
		break;
		case AEM_DKIM_RSA_512_SHA256:
			     if (lenDkimSignature == 512) email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_4096_SHA256;
			else if (lenDkimSignature == 256) email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_2048_SHA256;
			else if (lenDkimSignature == 128) email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_1024_SHA256;
			else if (lenDkimSignature != 64) {email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_BAD_SHA256; syslog(LOG_INFO, "RSA-SHA256=%d", lenDkimSignature);}
		break;
		case AEM_DKIM_RSA_512_SHA1:
			     if (lenDkimSignature == 256) email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_2048_SHA1;
			else if (lenDkimSignature == 128) email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_1024_SHA1;
			else if (lenDkimSignature != 64) {email->dkim[email->dkimCount].algo = AEM_DKIM_RSA_BAD_SHA1; syslog(LOG_INFO, "RSA-SHA1=%d", lenDkimSignature);}
		break;
	}

	// Verify bodyhash
	// Remove extra linebreaks at end
	while (lenBody > 4 && memeq(headEnd + lenBody - 4, "\r\n\r\n", 4)) lenBody -= 2;
	if (lenTrunc > lenBody) lenTrunc = 0;

	unsigned char calc_bodyhash[lenHash];
	if (lenHash == 20) {
		wc_ShaHash(headEnd, (lenTrunc > 0) ? lenTrunc : lenBody, calc_bodyhash);
	} else {
		wc_Sha256Hash(headEnd, (lenTrunc > 0) ? lenTrunc : lenBody, calc_bodyhash);
	}

	if (memeq(calc_bodyhash, dkim_bodyhash, lenHash)) {
		email->dkim[email->dkimCount].bodyHash = AEM_DKIM_HASH_PASS_SIMPLE;
	} else {
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

		if (lenHash == 20) {
			wc_ShaHash(relaxed, (lenTrunc > 0) ? lenTrunc : lenRelaxed, calc_bodyhash);
		} else {
			wc_Sha256Hash(relaxed, (lenTrunc > 0) ? lenTrunc : lenRelaxed, calc_bodyhash);
		}

		email->dkim[email->dkimCount].bodyHash = (memeq(calc_bodyhash, dkim_bodyhash, lenHash)) ? AEM_DKIM_HASH_PASS_RELAX : AEM_DKIM_HASH_FAIL;
	}

	RsaKey pk;
	if (wc_InitRsaKey(&pk, NULL) != 0) {syslog(LOG_ERR, "wc_InitRsaKey failed"); return offset;}
	word32 idx = 0;
	const int ret = wc_RsaPublicKeyDecode(pkBin, &idx, &pk, lenPkBin);
	if (ret != 0) {
		syslog(LOG_INFO, "Failed decoding public key: %d [%zd]\n", ret, lenPkBin);
	} else {
		verifyDkimSig(email, &pk, dkim_signature, lenDkimSignature, copyHeaders, dkimHeader + offset, headEnd - dkimHeader - offset - 4, dh, lenDh, lenHash);
	}

	wc_FreeRsaKey(&pk);
	(email->dkimCount)++;

	return offset;
}
