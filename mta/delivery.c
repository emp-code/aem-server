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

#include "../Common/Addr32.h"
#include "../Common/UnixSocketClient.h"

#include "delivery.h"

#include "../Global.h"

static unsigned char upk[crypto_box_PUBLICKEYBYTES];

static unsigned char sign_skey[crypto_sign_SECRETKEYBYTES];

void setSignKey(const unsigned char * const seed) {
	unsigned char tmp[crypto_sign_PUBLICKEYBYTES];
	crypto_sign_seed_keypair(tmp, sign_skey, seed);
}

#include "../Common/Message.c"

static int getPublicKey(const unsigned char * const addr32, const bool isShield) {
	const int sock = accountSocket(isShield ? AEM_MTA_GETPUBKEY_SHIELD : AEM_MTA_GETPUBKEY_NORMAL, addr32, 10);
	if (sock < 0) return -1;

	const ssize_t ret = recv(sock, upk, crypto_box_PUBLICKEYBYTES, 0);
	close(sock);
	return (ret == crypto_box_PUBLICKEYBYTES) ? 0 : -1;
}

__attribute__((warn_unused_result))
static unsigned char *makeExtMsg(struct emailInfo * const email, size_t * const lenOut) {
	if (email->lenBody > AEM_EXTMSG_BODY_MAXLEN) return NULL;

	if (email->lenHeaderTo >  63) email->lenHeaderTo =  63;
	if (email->lenGreeting > 127) email->lenGreeting = 127;
	if (email->lenRdns     > 127) email->lenRdns     = 127;

	// Data to be compressed
	const size_t lenUncomp = email->lenGreeting + email->lenRdns + email->lenEnvTo + email->lenHeaderTo + email->lenEnvFrom + email->lenHeaderFrom + email->lenMsgId + email->lenSubject + 4 + email->lenHead + email->lenBody;
	unsigned char * const uncomp = malloc(lenUncomp);
	if (uncomp == NULL) return NULL;

	size_t offset = 0;

	// The four short text fields
	memcpy(uncomp + offset, email->envTo,    email->lenEnvTo);    offset += email->lenEnvTo;
	memcpy(uncomp + offset, email->headerTo, email->lenHeaderTo); offset += email->lenHeaderTo;
	memcpy(uncomp + offset, email->greeting, email->lenGreeting); offset += email->lenGreeting;
	memcpy(uncomp + offset, email->rdns,     email->lenRdns);     offset += email->lenRdns;

	// The four long text fields
	memcpy(uncomp + offset, email->envFrom,    email->lenEnvFrom);    offset += email->lenEnvFrom;    uncomp[offset] = '\n'; offset++;
	memcpy(uncomp + offset, email->headerFrom, email->lenHeaderFrom); offset += email->lenHeaderFrom; uncomp[offset] = '\n'; offset++;
	memcpy(uncomp + offset, email->msgId,      email->lenMsgId);      offset += email->lenMsgId;      uncomp[offset] = '\n'; offset++;
	memcpy(uncomp + offset, email->subject,    email->lenSubject);    offset += email->lenSubject; // email->head begins with a linebreak

	// The headers and body
	memcpy(uncomp + offset, email->head, email->lenHead);
	offset += email->lenHead;
	uncomp[offset] = '\r'; offset++;
	memcpy(uncomp + offset, email->body, email->lenBody);

	// Compress
	size_t lenComp = lenUncomp + 256; // +256 in case compressed is larger
	unsigned char * const comp = malloc(lenComp);
	if (comp == NULL) {
		free(uncomp);
		return NULL;
	}

	if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_DEFAULT_MODE, lenUncomp, uncomp, &lenComp, comp) == BROTLI_FALSE) {
		free(uncomp);
		free(comp);
		return NULL;
	}

	free(uncomp);

	// Create the ExtMsg
	const size_t lenContent = 23 + ((email->dkimCount & 7) * 4) + lenComp;
	unsigned char * const content = malloc(lenContent);
	if (content == NULL) {
		free(comp);
		return NULL;
	}

	// Universal Part
	content[0] = msg_getPadAmount(lenContent);
	memcpy(content + 1, &(email->timestamp), 4);

	// ExtMsg Part
	memcpy(content + 5, &email->ip, 4);
	memcpy(content + 9, &email->tls_ciphersuite, 2);
	memcpy(content + 11, &email->tlsInfo, 2);

	// The 8 InfoBytes
	content[13] = ((email->dkimCount & 7) << 5) | (email->attachCount & 31);

	content[14] = email->ccBytes[0];
	if (email->protocolEsmtp)     content[14] |= 128;
	if (email->quitReceived)      content[14] |=  64;
	if (email->protocolViolation) content[14] |=  32;

	content[15] = email->ccBytes[1];
	if (email->invalidCommands) content[15] |= 128;
	if (email->rareCommands)    content[15] |=  64;
	if (email->toMultiple)      content[15] |=  32;

	content[16] = (email->spf & 192) | (email->lenEnvTo & 31);
	if (email->greetingIpMatch) content[16] |=  32;

	content[17] = (email->dmarc & 192) | (email->lenHeaderTo & 63);

	content[18] = email->lenGreeting & 127;
	if (email->ipBlacklisted) content[18] |= 128;

	content[19] = email->lenRdns & 127;
	if (email->dnssec) content[19] |= 128;

	content[20] = email->headerTz & 127;
	if (email->dane) content[20] |= 128;

	memcpy(content + 21, &email->headerTs, 2);

	// DKIM
	offset = 23;
	for (int i = 0; i < (email->dkimCount & 7); i++) {
		memcpy(content + offset, email->dkimInfo[i], 4);
		offset += 4;
	}

	// The compressed body
	memcpy(content + offset, comp, lenComp);
	free(comp);

	// Encrypt into the final form
	unsigned char * const encrypted = msg_encrypt(upk, content, lenContent, lenOut);
	free(content);

	if (encrypted == NULL) syslog(LOG_ERR, "Failed creating encrypted message");

	return encrypted;
}

void deliverMessage(char to[][32], const int toCount, struct emailInfo * const email) {
	if (to == NULL || toCount < 1 || email == NULL || email->body == NULL || email->lenBody < 1) {syslog(LOG_ERR, "deliverMessage(): Empty"); return;}

	if (toCount > 1) email->toMultiple = true;
	if (email->attachCount >  31) email->attachCount =  31;

	// Deliver
	for (int i = 0; i < toCount; i++) {
		char toAddr[16];

		size_t lenToAddr = 0;
		for (size_t j = 0; j < strlen(to[i]); j++) {
			if (isalnum(to[i][j])) {
				if (lenToAddr > 15) {syslog(LOG_ERR, "Address overlong"); return;}
				toAddr[lenToAddr] = tolower(to[i][j]);
				lenToAddr++;
			}
		}

		unsigned char toAddr32[10];
		addr32_store(toAddr32, toAddr, lenToAddr);

		const int ret = getPublicKey(toAddr32, (lenToAddr == 16));
		if (ret != 0) continue;

		email->lenEnvTo = strlen(to[i]);
		if (email->lenEnvTo > 31) email->lenEnvTo = 31;
		memcpy(email->envTo, to[i], email->lenEnvTo);

		size_t lenEnc = 0;
		unsigned char *enc = makeExtMsg(email, &lenEnc);
		if (enc == NULL || lenEnc < 1 || lenEnc % 16 != 0) {
			syslog(LOG_ERR, "makeExtMsg failed (%zu)", lenEnc);
			continue;
		}

		// Deliver
		unsigned char sockMsg[2 + crypto_box_PUBLICKEYBYTES];
		memcpy(sockMsg, upk, crypto_box_PUBLICKEYBYTES);

		const int stoSock = storageSocket(AEM_MTA_INSERT, sockMsg, 2 + crypto_box_PUBLICKEYBYTES);
		if (stoSock >= 0) {
			uint16_t u = (lenEnc / 16) - AEM_MSG_MINBLOCKS;
			if (send(stoSock, &u, 2, 0) != 2) {
				syslog(LOG_ERR, "Failed sending to Storage (1)");
				close(stoSock);
				continue;
			}

			if (send(stoSock, enc, lenEnc, 0) != (ssize_t)lenEnc) {
				syslog(LOG_ERR, "Failed sending to Storage (2)");
				close(stoSock);
				continue;
			}

			unsigned char msgId[16];
			memcpy(msgId, enc, 16);
			free(enc);

			// Store attachments
			for (int i = 0; i < email->attachCount; i++) {
				if (email->attachment[i] == NULL) {syslog(LOG_ERR, "Attachment null"); break;}

				unsigned char * const att = malloc(5 + email->lenAttachment[i]);
				att[0] = msg_getPadAmount(5 + email->lenAttachment[i]) | 32;
				memcpy(att + 1, &(email->timestamp), 4);
				memcpy(att + 5, email->attachment[i], email->lenAttachment[i]);
				memcpy(att + 6, msgId, 16);

				enc = msg_encrypt(upk, att, 5 + email->lenAttachment[i], &lenEnc);
				free(att);

				if (enc != NULL && lenEnc > 0 && lenEnc % 16 == 0) {
					u = (lenEnc / 16) - AEM_MSG_MINBLOCKS;
					if (send(stoSock, &u, 2, 0) != 2) {
						syslog(LOG_ERR, "Failed sending to Storage (3)");
						close(stoSock);
						continue;
					}

					if (send(stoSock, enc, lenEnc, 0) != (ssize_t)lenEnc) syslog(LOG_ERR, "Failed sending to Storage (4)");
				} else syslog(LOG_ERR, "Failed msg_encrypt()");

				if (enc != NULL) free(enc);
			}

			u = 0;
			send(stoSock, &u, 2, 0);
			close(stoSock);
		}
	}

	for (int i = 0; i < email->attachCount; i++) {
		if (email->attachment[i] == NULL) break;
		free(email->attachment[i]);
	}
}
