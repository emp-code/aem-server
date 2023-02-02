#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <brotli/encode.h>
#include <sodium.h>

#include "../Common/Email.h"
#include "../Common/memeq.h"

static unsigned char sign_skey[crypto_sign_SECRETKEYBYTES];

void setSignKey(const unsigned char * const baseKey) {
	unsigned char seed[crypto_sign_SEEDBYTES];
	crypto_kdf_derive_from_key(seed, crypto_sign_SEEDBYTES, 1, "AEM_Dlv1", baseKey);

	unsigned char tmp[crypto_sign_PUBLICKEYBYTES];
	crypto_sign_seed_keypair(tmp, sign_skey, seed);

	sodium_memzero(tmp, crypto_sign_PUBLICKEYBYTES);
	sodium_memzero(seed, crypto_sign_SEEDBYTES);
}

void delSignKey(void) {
	sodium_memzero(sign_skey, crypto_sign_SECRETKEYBYTES);
}

#include "../Common/Message.c"

__attribute__((warn_unused_result))
unsigned char *makeAttachment(const unsigned char * const upk, const unsigned char * const data, const size_t lenData, const uint32_t ts, const unsigned char parentId[16], size_t * const lenEnc) {
	if (data == NULL || lenData < 1) return NULL;

	const size_t lenAtt = 5 + lenData;
	unsigned char * const att = malloc(lenAtt);
	if (att == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}

	att[0] = msg_getPadAmount(lenAtt) | 32;
	memcpy(att + 1, &ts, 4);
	memcpy(att + 5, data, lenData);
	memcpy(att + 6, parentId, 16); // missing in original data

	unsigned char * const enc = msg_encrypt(upk, att, lenAtt, lenEnc);
	sodium_memzero(att, lenAtt);
	free(att);
	return enc;
}

__attribute__((warn_unused_result))
unsigned char *makeExtMsg(struct emailInfo * const email, const unsigned char * const upk, size_t * const lenOut, const bool allVer) {
	if (!allVer && email->body != NULL && email->lenBody > 0) { // Remove non-preferred variant(s) if requested
		const unsigned char * const r = memrchr(email->body, AEM_CET_CHAR_SEP, email->lenBody);
		if (r != NULL) {
			const size_t lenRem = (r + 1 - email->body);
			memmove(email->body, r + 1, email->lenBody - lenRem);
			email->lenBody -= lenRem;
		}
	}

	if (email->lenEnvTo > 63) email->lenEnvTo = 63;
	if (email->lenHdrTo > 63) email->lenHdrTo = 63;
	if (email->lenGreet > 63) email->lenGreet = 63;
	if (email->lenRvDns > 63) email->lenRvDns = 63;
	if (email->lenAuSys > 63) email->lenAuSys = 63;

	size_t lenUncomp =
		  email->lenEnvTo
		+ email->lenHdrTo
		+ email->lenGreet
		+ email->lenRvDns
		+ email->lenAuSys
		+ email->lenEnvFr
		+ email->lenHdrFr
		+ email->lenHdrRt
		+ email->lenMsgId
		+ email->lenSbjct
		+ ((email->lenHead <= 1) ? 0 : email->lenHead - 1)
		+ ((email->lenBody <  1) ? 0 : email->lenBody + 1);

	if (email->dkimCount > 7) email->dkimCount = 7;
	if (email->dkimCount > 6) lenUncomp += email->dkim[6].lenDomain;
	if (email->dkimCount > 5) lenUncomp += email->dkim[5].lenDomain;
	if (email->dkimCount > 4) lenUncomp += email->dkim[4].lenDomain;
	if (email->dkimCount > 3) lenUncomp += email->dkim[3].lenDomain;
	if (email->dkimCount > 2) lenUncomp += email->dkim[2].lenDomain;
	if (email->dkimCount > 1) lenUncomp += email->dkim[1].lenDomain;
	if (email->dkimCount > 0) lenUncomp += email->dkim[0].lenDomain;

	unsigned char * const uncomp = malloc(lenUncomp);
	if (uncomp == NULL) return NULL;

	size_t offset = 0;

	// DKIM domains
	for (int i = 0; i < email->dkimCount; i++) {
		memcpy(uncomp + offset, email->dkim[i].domain, email->dkim[i].lenDomain);
		offset += email->dkim[i].lenDomain;
	}

	// The five short-text fields
	memcpy(uncomp + offset, email->envTo, email->lenEnvTo); offset += email->lenEnvTo;
	memcpy(uncomp + offset, email->hdrTo, email->lenHdrTo); offset += email->lenHdrTo;
	memcpy(uncomp + offset, email->greet, email->lenGreet); offset += email->lenGreet;
	memcpy(uncomp + offset, email->rvDns, email->lenRvDns); offset += email->lenRvDns;
	memcpy(uncomp + offset, email->auSys, email->lenAuSys); offset += email->lenAuSys;

	// The five long-text fields
	memcpy(uncomp + offset, email->envFr, email->lenEnvFr); offset += email->lenEnvFr;
	memcpy(uncomp + offset, email->hdrFr, email->lenHdrFr); offset += email->lenHdrFr;
	memcpy(uncomp + offset, email->hdrRt, email->lenHdrRt); offset += email->lenHdrRt;
	memcpy(uncomp + offset, email->msgId, email->lenMsgId); offset += email->lenMsgId;
	memcpy(uncomp + offset, email->sbjct, email->lenSbjct); offset += email->lenSbjct;

	// The headers and body
	if (email->lenHead > 1) {
		memcpy(uncomp + offset, email->head + 1, email->lenHead - 1); // Ignore leading linebreak
		offset += email->lenHead - 1;
	}

	if (email->lenBody > 0) {
		uncomp[offset] = AEM_CET_CHAR_SEP;
		offset++;
		memcpy(uncomp + offset, email->body, email->lenBody);
	}

	// Compress the data
	const size_t lenHead = 28 + (email->dkimCount * 3);
	size_t lenContent = lenUncomp + 300; // 300 for potential compression overhead
	unsigned char * const content = malloc(lenContent + lenHead);
	if (content == NULL) {
		free(uncomp);
		return NULL;
	}

	if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_DEFAULT_MODE, lenUncomp, uncomp, &lenContent, content + lenHead) == BROTLI_FALSE) {
		free(uncomp);
		free(content);
		return NULL;
	}

	free(uncomp);

	// Create the ExtMsg
	lenContent += lenHead;
	if (lenContent + crypto_sign_BYTES + crypto_box_SEALBYTES > AEM_MSG_MAXSIZE) {
		free(content);
		return NULL;
	}

	// Universal Part
	content[0] = msg_getPadAmount(lenContent);
	memcpy(content + 1, &(email->timestamp), 4);

	// ExtMsg Part
	memcpy(content + 5, &email->ip, 4);
	memcpy(content + 9, &email->tls_ciphersuite, 2);
	content[11] = email->tlsInfo;

	// InfoBytes
	content[12] = (email->dkimCount << 5) | (email->attachCount & 31); // InfoByte #1: DKIM & Attachments

	content[13] = email->ccBytes[0]; // InfoByte #2
	if (email->ipBlacklisted)   content[13] |= 128;
	if (email->ipMatchGreeting) content[13] |=  64;
	if (email->protocolEsmtp)   content[13] |=  32;

	content[14] = email->ccBytes[1]; // InfoByte #3
	if (email->invalidCommands)   content[14] |= 128;
	if (email->protocolViolation) content[14] |=  63;
	if (email->rareCommands)      content[14] |=  32;

	content[15] = (email->spf   & 192) | (email->lenEnvTo & 63); // InfoByte #4
	content[16] = (email->dmarc & 192) | (email->lenHdrTo & 63); // InfoByte #5

	// InfoByte #6
	content[17] = email->lenGreet & 63;
	if (email->dnssec) content[17] |= 128;

	// InfoByte #7
	content[18] = email->lenRvDns & 63;
	if (email->dane) content[18] |= 128;

	// InfoByte #8
	content[19] = email->lenAuSys & 63;
	// [19] & 192 unused

	// InfoBytes #9-13: Long-Text lengths; potential space for future expansion by reducing max lengths
	content[20] = email->lenEnvFr & 255;
	content[21] = email->lenHdrFr & 255;
	content[22] = email->lenHdrRt & 255;
	content[23] = email->lenMsgId & 255;
	content[24] = email->lenSbjct & 255;

	// Final InfoByte (#14) + HeaderTs
	content[25] = email->hdrTz & 127;
	if (email->dkimFailed) content[25] |= 128;
	memcpy(content + 26, &email->hdrTs, 2);

	// DKIM
	offset = 28;
	for (int i = 0; i < email->dkimCount; i++) {
		if (email->dkim[i].algoRsa)    content[offset] |= 128;
		if (email->dkim[i].algoSha256) content[offset] |=  64;
		if (email->dkim[i].dnsFlag_s)  content[offset] |=  32;
		if (email->dkim[i].dnsFlag_y)  content[offset] |=  16;
		if (email->dkim[i].headSimple) content[offset] |=   8;
		if (email->dkim[i].bodySimple) content[offset] |=   4;

		const int64_t expiry = email->dkim[i].ts_expr - email->timestamp;
		// 0: Expired
		if (email->dkim[i].ts_expr == 0) content[offset] |= 1; // 1: Expiration disabled or value invalid
		else if (expiry >= 2629746)      content[offset] |= 2; // 2: Long expiration: >= 1 month
		else if (expiry >  0)            content[offset] |= 3; // 3: Short expiration: < 1 month

		if (email->dkim[i].fullId)     content[offset + 1] |= 128;
		if (email->dkim[i].sgnAll)     content[offset + 1] |=  64;
		if (email->dkim[i].sgnDate)    content[offset + 1] |=  32;
		if (email->dkim[i].sgnFrom)    content[offset + 1] |=  16;
		if (email->dkim[i].sgnMsgId)   content[offset + 1] |=   8;
		if (email->dkim[i].sgnReplyTo) content[offset + 1] |=   4;
		if (email->dkim[i].sgnSubject) content[offset + 1] |=   2;
		if (email->dkim[i].sgnTo)      content[offset + 1] |=   1;

		if (email->dkim[i].bodyTrunc)  content[offset + 2] |= 128;
		if ((int64_t)email->timestamp - email->dkim[i].ts_sign > 30) content[offset + 2] |= 64;
		content[offset + 2] |= (email->dkim[i].lenDomain - 4) & 63;

		offset += 3;
	}

	// Encrypt into the final form
	unsigned char throwaway[crypto_box_PUBLICKEYBYTES];
	randombytes_buf(throwaway, crypto_box_PUBLICKEYBYTES);

	unsigned char * const encrypted = msg_encrypt(sodium_is_zero(upk, crypto_box_PUBLICKEYBYTES) ? throwaway : upk, content, lenContent, lenOut);
	sodium_memzero(content, lenContent);
	free(content);
	if (encrypted == NULL) syslog(LOG_ERR, "Failed creating encrypted message");

	return encrypted;
}
