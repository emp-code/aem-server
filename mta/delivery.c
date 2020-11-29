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
static unsigned char *makeExtMsg(const unsigned char * const body, size_t * const lenBody, const struct emailInfo * const email) {
	if (*lenBody > AEM_EXTMSG_BODY_MAXLEN) *lenBody = AEM_EXTMSG_BODY_MAXLEN;

	const size_t lenContent = AEM_EXTMSG_HEADERS_LEN + *lenBody;
	unsigned char * const content = sodium_malloc(lenContent);

	const uint16_t cs16 = (email->tls_ciphersuite > UINT16_MAX || email->tls_ciphersuite < 0) ? 1 : email->tls_ciphersuite;

	uint8_t infoBytes[8];
	infoBytes[0] = (email->tls_version << 5) | (email->attachCount & 31);
	infoBytes[1] = isupper(email->countryCode[0]) ? email->countryCode[0] - 'A' : 31;
	infoBytes[2] = isupper(email->countryCode[1]) ? email->countryCode[1] - 'A' : 31;
	infoBytes[3] = 0;
	infoBytes[4] = email->lenGreeting & 127;
	infoBytes[5] = email->lenRdns     & 127;
	infoBytes[6] = email->lenCharset  & 127;
	infoBytes[7] = email->lenEnvFrom  & 127;

	if (email->isShield) infoBytes[4] |= 128;

	if (email->protocolEsmtp)     infoBytes[1] |= 128;
	if (email->quitReceived)      infoBytes[1] |=  64;
	if (email->protocolViolation) infoBytes[1] |=  32;

	if (email->invalidCommands) infoBytes[2] |=  128;
	if (email->rareCommands)    infoBytes[2] |=  64;
	// [2] & 32 unused

	content[0] = msg_getPadAmount(lenContent);
	memcpy(content + 1, &(email->timestamp), 4);
	memcpy(content + 5, &(email->ip), 4);
	memcpy(content + 9, &cs16, 2);
	memcpy(content + 11, infoBytes, 8);
	memcpy(content + 19, email->toAddr32, 10);
	memcpy(content + 29, body, *lenBody);

	unsigned char * const encrypted = msg_encrypt(upk, content, lenContent, lenBody);
	sodium_free(content);
	if (encrypted == NULL) {
		syslog(LOG_ERR, "Failed creating encrypted message");
		return NULL;
	}

	return encrypted;
}

void deliverMessage(const char * const to, const size_t lenToTotal, const unsigned char * const msgBody, size_t lenMsgBody, struct emailInfo * const email) {
	if (to == NULL || lenToTotal < 1 || msgBody == NULL || lenMsgBody < 1 || email == NULL) return;

	if (email->attachCount > 31) email->attachCount = 31;
	if (email->tls_version >  7) email->tls_version =  7;

	if (email->lenGreeting > 127) email->lenGreeting = 127;
	if (email->lenRdns     > 127) email->lenRdns     = 127;
	if (email->lenCharset  > 127) email->lenCharset  = 127;
	if (email->lenEnvFrom  > 127) email->lenEnvFrom  = 127;

	const char *toStart = to;
	const char * const toEnd = to + lenToTotal;

	while(1) {
		char * const nextTo = memchr(toStart, '\n', toEnd - toStart);
		const size_t lenTo = ((nextTo != NULL) ? nextTo : toEnd) - toStart;
		if (lenTo < 1 || lenTo > 16) {syslog(LOG_ERR, "deliverMessage: Invalid receiver address length"); break;}

		addr32_store(email->toAddr32, toStart, lenTo);
		email->isShield = (lenTo == 16);

		const int ret = getPublicKey(email->toAddr32, email->isShield);
		if (ret != 0) {
			if (nextTo == NULL) break;
			toStart = nextTo + 1;
			continue;
		}

		unsigned char *enc = makeExtMsg(msgBody, &lenMsgBody, email);
		size_t lenEnc = lenMsgBody;
		if (enc == NULL || lenEnc < 1 || lenEnc % 16 != 0) {
			syslog(LOG_ERR, "makeExtMsg failed (%zu)", lenEnc);
			if (nextTo == NULL) break;
			toStart = nextTo + 1;
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

				unsigned char * const att = malloc(5 + email->attachSize[i]);
				att[0] = msg_getPadAmount(5 + email->attachSize[i]) | 32;
				memcpy(att + 1, &(email->timestamp), 4);
				memcpy(att + 5, email->attachment[i], email->attachSize[i]);
				memcpy(att + 6, msgId, 16);

				enc = msg_encrypt(upk, att, 5 + email->attachSize[i], &lenEnc);
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

		if (nextTo == NULL) break;
		toStart = nextTo + 1;
	}

	for (int i = 0; i < email->attachCount; i++) {
		if (email->attachment[i] == NULL) break;
		free(email->attachment[i]);
	}
}
