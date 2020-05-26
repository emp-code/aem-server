#define _GNU_SOURCE // for peercred

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include <sodium.h>

#include "Include/Addr32.h"

#include "delivery.h"

#include "../Global.h"

static unsigned char upk[crypto_box_PUBLICKEYBYTES];

static unsigned char accessKey_account[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage[AEM_LEN_ACCESSKEY];

static unsigned char sign_skey[crypto_sign_SECRETKEYBYTES];

static pid_t pid_account = 0;
static pid_t pid_storage = 0;

void setAccessKey_account(const unsigned char * const newKey) {memcpy(accessKey_account, newKey, AEM_LEN_ACCESSKEY);}
void setAccessKey_storage(const unsigned char * const newKey) {memcpy(accessKey_storage, newKey, AEM_LEN_ACCESSKEY);}

void setSignKey(const unsigned char * const seed) {
	unsigned char tmp[crypto_sign_PUBLICKEYBYTES];
	crypto_sign_seed_keypair(tmp, sign_skey, seed);
}

void setAccountPid(const pid_t pid) {pid_account = pid;}
void setStoragePid(const pid_t pid) {pid_storage = pid;}

#include "../Common/UnixSocketClient.c"
#include "../Common/Message.c"

static int getPublicKey(const unsigned char * const addr32, const bool isShield) {
	const int sock = accountSocket(isShield ? AEM_MTA_GETPUBKEY_SHIELD : AEM_MTA_GETPUBKEY_NORMAL, addr32, 15);
	if (sock < 0) return -1;

	const ssize_t ret = recv(sock, upk, crypto_box_PUBLICKEYBYTES, 0);
	close(sock);
	return (ret == crypto_box_PUBLICKEYBYTES) ? 0 : -1;
}

__attribute__((warn_unused_result))
unsigned char *makeExtMsg(const unsigned char * const body, size_t * const lenBody, const struct emailInfo email) {
	if (*lenBody > AEM_EXTMSG_BODY_MAXLEN) *lenBody = AEM_EXTMSG_BODY_MAXLEN;

	const size_t lenContent = AEM_EXTMSG_HEADERS_LEN + *lenBody;
	unsigned char * const content = sodium_malloc(lenContent);

	const uint16_t padAmount16 = (msg_getPadAmount(lenContent) << 6); // ExtMsg: 32=0/16=0; 8/4/2/1=unused
	const uint16_t cs16 = (email.tls_ciphersuite > UINT16_MAX || email.tls_ciphersuite < 0) ? 1 : email.tls_ciphersuite;

	uint8_t infoBytes[9];
	infoBytes[0] = (email.tls_version << 5) | email.attachments;
	infoBytes[1] = isupper(email.countryCode[0]) ? email.countryCode[0] - 'A' : 31;
	infoBytes[2] = isupper(email.countryCode[1]) ? email.countryCode[1] - 'A' : 31;
	infoBytes[3] = 0;
	infoBytes[4] = 0;
	infoBytes[5] = email.lenGreeting & 127;
	infoBytes[6] = email.lenRdns     & 127;
	infoBytes[7] = email.lenCharset  & 127;
	infoBytes[8] = email.lenEnvFrom  & 127;

	if (email.isShield) infoBytes[5] |= 128;

	if (email.protocolEsmtp)     infoBytes[1] |= 128;
	if (email.quitReceived)      infoBytes[1] |=  64;
	if (email.protocolViolation) infoBytes[1] |=  32;

	if (email.invalidCommands) infoBytes[2] |=  128;
	if (email.rareCommands)    infoBytes[2] |=  64;
	// [2] & 32 unused

	memcpy(content, &padAmount16, 2);
	memcpy(content + 2, &(email.timestamp), 4);
	memcpy(content + 6, &(email.ip), 4);
	memcpy(content + 10, &cs16, 2);
	memcpy(content + 12, infoBytes, 9);
	memcpy(content + 21, email.toAddr32, 15);
	memcpy(content + 36, body, *lenBody);

	unsigned char * const encrypted = msg_encrypt(content, lenContent, lenBody);
	sodium_free(content);
	if (encrypted == NULL) {
		syslog(LOG_ERR, "Failed creating encrypted message");
		return NULL;
	}

	return encrypted;
}

void deliverMessage(const char * const to, const size_t lenToTotal, const unsigned char * const msgBody, size_t lenMsgBody, struct emailInfo email) {
	if (to == NULL || lenToTotal < 1 || msgBody == NULL || lenMsgBody < 1) return;

	if (email.attachments > 31) email.attachments = 31;
	if (email.tls_version > 7) email.tls_version = 7;

	if (email.lenGreeting > 127) email.lenGreeting = 127;
	if (email.lenRdns     > 127) email.lenRdns     = 127;
	if (email.lenCharset  > 127) email.lenCharset  = 127;
	if (email.lenEnvFrom  > 127) email.lenEnvFrom  = 127;

	const char *toStart = to;
	const char * const toEnd = to + lenToTotal;

	while(1) {
		char * const nextTo = memchr(toStart, '\n', toEnd - toStart);
		const size_t lenTo = ((nextTo != NULL) ? nextTo : toEnd) - toStart;
		if (lenTo < 1 || lenTo > 24) {syslog(LOG_ERR, "deliverMessage: Invalid receiver address length"); break;}

		unsigned char addr32[15];
		addr32_store(addr32, toStart, lenTo);
		memcpy(email.toAddr32, addr32, 15);
		email.isShield = (lenTo == 24);

		const int ret = getPublicKey(addr32, lenTo == 24);
		if (ret != 0) {
			if (nextTo == NULL) break;
			toStart = nextTo + 1;
			continue;
		}

		unsigned char * const box = makeExtMsg(msgBody, &lenMsgBody, email);
		if (box == NULL || lenMsgBody < 1 || lenMsgBody % 1024 != 0) {
			syslog(LOG_ERR, "makeExtMsg failed (%zu)", lenMsgBody);
			if (nextTo == NULL) break;
			toStart = nextTo + 1;
			continue;
		}

		// Deliver
		const int stoSock = storageSocket(lenMsgBody / 1024, upk, crypto_box_PUBLICKEYBYTES);
		if (stoSock >= 0) {
			if (send(stoSock, box, lenMsgBody, 0) != (ssize_t)lenMsgBody) syslog(LOG_ERR, "Failed sending to Storage");
		}

		free(box);
		close(stoSock);

		if (nextTo == NULL) break;
		toStart = nextTo + 1;
	}
}
