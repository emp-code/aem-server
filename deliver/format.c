#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
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
	if (email->dkimCount > 6) lenUncomp += email->dkim[6].lenDomain + email->dkim[6].lenSelector + email->dkim[6].lenNotes;
	if (email->dkimCount > 5) lenUncomp += email->dkim[5].lenDomain + email->dkim[5].lenSelector + email->dkim[5].lenNotes;
	if (email->dkimCount > 4) lenUncomp += email->dkim[4].lenDomain + email->dkim[4].lenSelector + email->dkim[4].lenNotes;
	if (email->dkimCount > 3) lenUncomp += email->dkim[3].lenDomain + email->dkim[3].lenSelector + email->dkim[3].lenNotes;
	if (email->dkimCount > 2) lenUncomp += email->dkim[2].lenDomain + email->dkim[2].lenSelector + email->dkim[2].lenNotes;
	if (email->dkimCount > 1) lenUncomp += email->dkim[1].lenDomain + email->dkim[1].lenSelector + email->dkim[1].lenNotes;
	if (email->dkimCount > 0) lenUncomp += email->dkim[0].lenDomain + email->dkim[0].lenSelector + email->dkim[0].lenNotes;

	for (int d = 0; d < email->dkimCount; d++) {
		if (email->dkim[d].lenIdentity > 0) {
			if (email->dkim[d].lenIdentity == email->lenEnvFr && memeq(email->dkim[d].identity, email->envFr, email->lenEnvFr))
			  email->dkim[d].idValue = AEM_DKIM_IDENTITY_EF;

			else if ((email->dkim[d].lenIdentity == email->lenHdrFr && memeq(email->dkim[d].identity, email->hdrFr, email->lenHdrFr)) ||
			(email->lenHdrFr > email->dkim[d].lenIdentity && email->hdrFr[email->lenHdrFr - email->dkim[d].lenIdentity - 1] == 0x7F && memeq(email->dkim[d].identity, email->hdrFr + email->lenHdrFr - email->dkim[d].lenIdentity, email->dkim[d].lenIdentity))
			) email->dkim[d].idValue = AEM_DKIM_IDENTITY_HF;

			else if ((email->dkim[d].lenIdentity == email->lenHdrRt && memeq(email->dkim[d].identity, email->hdrRt, email->lenHdrRt)) ||
			(email->lenHdrRt > email->dkim[d].lenIdentity && email->hdrRt[email->lenHdrRt - email->dkim[d].lenIdentity - 1] == 0x7F && memeq(email->dkim[d].identity, email->hdrRt + email->lenHdrRt - email->dkim[d].lenIdentity, email->dkim[d].lenIdentity))
			) email->dkim[d].idValue = AEM_DKIM_IDENTITY_RT;
		}
	}

	unsigned char * const uncomp = malloc(lenUncomp);
	if (uncomp == NULL) {syslog(LOG_ERR, "Failed malloc"); return NULL;}

	size_t offset = 0;

	// DKIM domains
	for (int i = 0; i < email->dkimCount; i++) {
		if (email->dkim[i].lenDomain   > 0) memcpy(uncomp + offset, email->dkim[i].domain,   email->dkim[i].lenDomain);
		offset += email->dkim[i].lenDomain;
		if (email->dkim[i].lenSelector > 0) memcpy(uncomp + offset, email->dkim[i].selector, email->dkim[i].lenSelector);
		offset += email->dkim[i].lenSelector;
		if (email->dkim[i].lenNotes    > 0) memcpy(uncomp + offset, email->dkim[i].notes,    email->dkim[i].lenNotes);
		offset += email->dkim[i].lenNotes;
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
	const size_t lenHead = AEM_MSG_HDR_SZ + 23 + (email->dkimCount * AEM_DKIM_INFOBYTES); // 23: ExtMsg header
	size_t lenBody = lenUncomp + 300; // 300 for overhead
	unsigned char * const msg = malloc(lenHead + lenBody);
	if (msg == NULL) {
		syslog(LOG_ERR, "Failed malloc");
		free(uncomp);
		return NULL;
	}

	if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_DEFAULT_MODE, lenUncomp, uncomp, &lenBody, msg + lenHead) == BROTLI_FALSE) {
		syslog(LOG_ERR, "Failed compression");
		free(uncomp);
		free(msg);
		return NULL;
	}

	free(uncomp);

	const size_t lenMsg = lenHead + lenBody;
	if (lenMsg > AEM_MSG_W_MAXSIZE) {
		free(msg);
		return NULL;
	}

// Message Header (AEM_MSG_HDR_SZ bytes)
	aem_msg_init(msg, AEM_MSG_TYPE_EXT, email->binTs);

// ExtMsg Header (23 bytes)
	memcpy(msg + AEM_MSG_HDR_SZ, &email->ip, 4);
	memcpy(msg + AEM_MSG_HDR_SZ + 4, &email->tls_ciphersuite, 2);
	msg[AEM_MSG_HDR_SZ + 6] = email->tlsInfo;

	// InfoBytes
	msg[AEM_MSG_HDR_SZ + 7] = (email->dkimCount << 5) | (email->attachCount & 31); // InfoByte #1: DKIM & Attachments

	msg[AEM_MSG_HDR_SZ + 8] = email->ccBytes[0]; // InfoByte #2
	if (email->ipBlacklisted)   msg[13] |= 128;
	if (email->ipMatchGreeting) msg[13] |=  64;
	if (email->protocolEsmtp)   msg[13] |=  32;

	msg[AEM_MSG_HDR_SZ + 9] = email->ccBytes[1]; // InfoByte #3
	if (email->invalidCommands)   msg[14] |= 128;
	if (email->protocolViolation) msg[14] |=  63;
	if (email->rareCommands)      msg[14] |=  32;

	msg[AEM_MSG_HDR_SZ + 10] = (email->spf   & 192) | (email->lenEnvTo & 63); // InfoByte #4
	msg[AEM_MSG_HDR_SZ + 11] = (email->dmarc & 192) | (email->lenHdrTo & 63); // InfoByte #5

	// InfoByte #6
	msg[AEM_MSG_HDR_SZ + 12] = email->lenGreet & 63;
	if (email->dnssec) msg[17] |= 128;

	// InfoByte #7
	msg[AEM_MSG_HDR_SZ + 13] = email->lenRvDns & 63;
	if (email->dane) msg[18] |= 128;

	// InfoByte #8
	msg[AEM_MSG_HDR_SZ + 14] = email->lenAuSys & 63;
	// [AEM_MSG_HDR_SZ + 14] & 192 unused

	// InfoBytes #9-13: Long-Text lengths; potential space for future expansion by reducing max lengths
	msg[AEM_MSG_HDR_SZ + 15] = email->lenEnvFr & 255;
	msg[AEM_MSG_HDR_SZ + 16] = email->lenHdrFr & 255;
	msg[AEM_MSG_HDR_SZ + 17] = email->lenHdrRt & 255;
	msg[AEM_MSG_HDR_SZ + 18] = email->lenMsgId & 255;
	msg[AEM_MSG_HDR_SZ + 19] = email->lenSbjct & 255;

	// Final InfoByte (#14) + HeaderTs
	// [AEM_MSG_HDR_SZ + 20] & 128 unused
	msg[AEM_MSG_HDR_SZ + 20] = email->hdrTz & 127;
	memcpy(msg + AEM_MSG_HDR_SZ + 21, &email->hdrTs, 2);

	// DKIM
	offset = AEM_MSG_HDR_SZ + 23;

	for (int i = 0; i < email->dkimCount; i++) {
		memcpy(msg + offset, &email->dkim[i], AEM_DKIM_INFOBYTES);
		offset += AEM_DKIM_INFOBYTES;
	}

	*lenOut = lenMsg;
	return msg;
}
