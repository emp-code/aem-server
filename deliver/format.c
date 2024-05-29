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
#include "../Common/Message.h"
#include "../Common/memeq.h"

#include "format.h"

__attribute__((warn_unused_result))
unsigned char *makeExtMsg(struct emailInfo * const email, size_t * const lenOut, const bool allVer) {
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
	if (uncomp == NULL) {syslog(LOG_ERR, "Failed malloc"); return NULL;}

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
	size_t lenContent = lenUncomp + 300; // 300 for compression/padding overhead
	unsigned char * const content = malloc(AEM_ENVELOPE_RESERVED_LEN + lenHead + lenContent);
	if (content == NULL) {
		free(uncomp);
		return NULL;
	}

	if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_DEFAULT_MODE, lenUncomp, uncomp, &lenContent, content + AEM_ENVELOPE_RESERVED_LEN + lenHead) == BROTLI_FALSE) {
		free(uncomp);
		free(content);
		return NULL;
	}

	free(uncomp);

	// Create the ExtMsg
	lenContent += AEM_ENVELOPE_RESERVED_LEN + lenHead;
	const int lenPadding = msg_getPadAmount(lenContent);
	randombytes_buf(content + lenContent, lenPadding);
	lenContent += lenPadding;

	if (lenContent < AEM_MSG_MINSIZE || lenContent > AEM_MSG_SRC_MAXSIZE) {
		free(content);
		return NULL;
	}

	unsigned char * const head = content + AEM_ENVELOPE_RESERVED_LEN;

// Universal part
	head[0] = lenPadding;
	memcpy(head + 1, &(email->timestamp), 4);

// ExtMsg Part
	memcpy(head + 5, &email->ip, 4);
	memcpy(head + 9, &email->tls_ciphersuite, 2);
	head[11] = email->tlsInfo;

	// InfoBytes
	head[12] = (email->dkimCount << 5) | (email->attachCount & 31); // InfoByte #1: DKIM & Attachments

	head[13] = email->ccBytes[0]; // InfoByte #2
	if (email->ipBlacklisted)   head[13] |= 128;
	if (email->ipMatchGreeting) head[13] |=  64;
	if (email->protocolEsmtp)   head[13] |=  32;

	head[14] = email->ccBytes[1]; // InfoByte #3
	if (email->invalidCommands)   head[14] |= 128;
	if (email->protocolViolation) head[14] |=  63;
	if (email->rareCommands)      head[14] |=  32;

	head[15] = (email->spf   & 192) | (email->lenEnvTo & 63); // InfoByte #4
	head[16] = (email->dmarc & 192) | (email->lenHdrTo & 63); // InfoByte #5

	// InfoByte #6
	head[17] = email->lenGreet & 63;
	if (email->dnssec) head[17] |= 128;

	// InfoByte #7
	head[18] = email->lenRvDns & 63;
	if (email->dane) head[18] |= 128;

	// InfoByte #8
	head[19] = email->lenAuSys & 63;
	// [19] & 192 unused

	// InfoBytes #9-13: Long-Text lengths; potential space for future expansion by reducing max lengths
	head[20] = email->lenEnvFr & 255;
	head[21] = email->lenHdrFr & 255;
	head[22] = email->lenHdrRt & 255;
	head[23] = email->lenMsgId & 255;
	head[24] = email->lenSbjct & 255;

	// Final InfoByte (#14) + HeaderTs
	head[25] = email->hdrTz & 127;
	if (email->dkimFailed) head[25] |= 128;
	memcpy(head + 26, &email->hdrTs, 2);

	// DKIM
	offset = 28;
	bzero(head + offset, email->dkimCount * 3);

	for (int i = 0; i < email->dkimCount; i++) {
		if (email->dkim[i].algoRsa)    head[offset] |= 128;
		if (email->dkim[i].algoSha256) head[offset] |=  64;
		if (email->dkim[i].dnsFlag_s)  head[offset] |=  32;
		if (email->dkim[i].dnsFlag_y)  head[offset] |=  16;
		if (email->dkim[i].headSimple) head[offset] |=   8;
		if (email->dkim[i].bodySimple) head[offset] |=   4;

		const int64_t expiry = email->dkim[i].ts_expr - email->timestamp;
		// 0: Expired
		if (email->dkim[i].ts_expr == 0) head[offset] |= 1; // 1: Expiration disabled or value invalid
		else if (expiry >= 2629746)      head[offset] |= 2; // 2: Long expiration: >= 1 month
		else if (expiry >  0)            head[offset] |= 3; // 3: Short expiration: < 1 month

		if (email->dkim[i].fullId)     head[offset + 1] |= 128;
		if (email->dkim[i].sgnAll)     head[offset + 1] |=  64;
		if (email->dkim[i].sgnDate)    head[offset + 1] |=  32;
		if (email->dkim[i].sgnFrom)    head[offset + 1] |=  16;
		if (email->dkim[i].sgnMsgId)   head[offset + 1] |=   8;
		if (email->dkim[i].sgnReplyTo) head[offset + 1] |=   4;
		if (email->dkim[i].sgnSubject) head[offset + 1] |=   2;
		if (email->dkim[i].sgnTo)      head[offset + 1] |=   1;

		if (email->dkim[i].bodyTrunc)  head[offset + 2] |= 128;
		if ((int64_t)email->timestamp - email->dkim[i].ts_sign > 30) head[offset + 2] |= 64;
		head[offset + 2] |= (email->dkim[i].lenDomain - 4) & 63;

		offset += 3;
	}

	*lenOut = lenContent;
	return content;
}
