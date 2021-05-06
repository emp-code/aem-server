#include <ctype.h> // for isalnum()
#include <math.h> // for abs()
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/Addr32.h"
#include "../Common/UnixSocketClient.h"
#include "../Common/ValidEmail.h"
#include "../Common/ValidUtf8.h"
#include "../Data/welcome.h"

#include "Error.h"
#include "MessageId.h"
#include "SendMail.h"

#include "post.h"

#define AEM_API_HTTP

static bool keepAlive;
static int postCmd;
static unsigned char postNonce[crypto_box_NONCEBYTES];

static unsigned char upk[crypto_box_PUBLICKEYBYTES];
static unsigned char *response = NULL;
static unsigned char *decrypted = NULL;
static int lenResponse;
static uint32_t lenDecrypted;

static unsigned char spk[crypto_box_PUBLICKEYBYTES];
static unsigned char ssk[crypto_box_SECRETKEYBYTES];
static unsigned char sign_skey[crypto_sign_SECRETKEYBYTES];

void setApiKey(const unsigned char * const seed) {
	crypto_box_seed_keypair(spk, ssk, seed);
}

void setSigKey(const unsigned char * const seed) {
	unsigned char tmp[crypto_sign_PUBLICKEYBYTES];
	crypto_sign_seed_keypair(tmp, sign_skey, seed);
}

int aem_api_init(void) {
	if (tlsSetup_sendmail() != 0) return -1;

	response = sodium_malloc(AEM_MAXLEN_MSGDATA + 9999); // enough for headers and account data
	if (response == NULL) return -1;

	decrypted = sodium_malloc(AEM_API_BOX_SIZE_MAX);
	return (decrypted != NULL) ? 0 : -1;
}

void aem_api_free(void) {
	sodium_memzero(spk, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(ssk, crypto_box_SECRETKEYBYTES);
	sodium_memzero(sign_skey, crypto_sign_SECRETKEYBYTES);
	sodium_memzero(upk, crypto_box_PUBLICKEYBYTES);
	sodium_free(decrypted);
	sodium_free(response);
	decrypted = NULL;

	tlsFree_sendmail();
}

static void clearDecrypted(void) {
	sodium_mprotect_readwrite(decrypted);
	sodium_memzero(decrypted, AEM_API_BOX_SIZE_MAX);
	sodium_mprotect_noaccess(decrypted);
}

#include "../Common/Message.c"

static void shortResponse(const unsigned char * const data, const unsigned char lenData) {
#ifndef AEM_IS_ONION
	#define AEM_LEN_SHORTRESPONSE_HEADERS 231
#else
	#define AEM_LEN_SHORTRESPONSE_HEADERS 120
#endif

	memcpy(response, keepAlive?
		"HTTP/1.1 200 aem\r\n"
#ifndef AEM_IS_ONION
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
#endif
		"Content-Length: 73\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: keep-alive\r\n"
		"Keep-Alive: timeout=30\r\n"
		"\r\n"
	:
		"HTTP/1.1 200 aem\r\n"
#ifndef AEM_IS_ONION
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
#endif
		"Content-Length: 73\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"Padding-Ignore: abcdefghijk\r\n"
		"\r\n"
	, AEM_LEN_SHORTRESPONSE_HEADERS);

	randombytes_buf(response + AEM_LEN_SHORTRESPONSE_HEADERS, crypto_box_NONCEBYTES);

	unsigned char clr[33];
	bzero(clr, 33);
	clr[0] = lenData;
	if (data != NULL && lenData <= 32) memcpy(clr + 1, data, lenData);

	const int ret = crypto_box_easy(response + AEM_LEN_SHORTRESPONSE_HEADERS + crypto_box_NONCEBYTES, clr, 33, response + AEM_LEN_SHORTRESPONSE_HEADERS, upk, ssk);
	if (ret == 0) lenResponse = AEM_LEN_SHORTRESPONSE_HEADERS + 33 + crypto_box_NONCEBYTES + crypto_box_MACBYTES;
}

static int numDigits(const size_t x) {
	return
	(x < 100 ? 2 :
	(x < 1000 ? 3 :
	(x < 10000 ? 4 :
	(x < 100000 ? 5 :
	(x < 1000000 ? 6 :
	7)))));
}

static void longResponse(const unsigned char * const data, const size_t lenData) {
#ifndef AEM_IS_ONION
	#define AEM_LEN_LONGRESPONSE_HEADERS 195
#else
	#define AEM_LEN_LONGRESPONSE_HEADERS 84
#endif

	const size_t lenEnc = lenData + crypto_box_NONCEBYTES + crypto_box_MACBYTES;

	sprintf((char*)response,
		"HTTP/1.1 200 aem\r\n"
#ifndef AEM_IS_ONION
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
#endif
		"Content-Length: %zu\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: %s\r\n"
		"\r\n",
	lenEnc, keepAlive ? "keep-alive\r\nKeep-Alive: timeout=30" : "close");

	const size_t lenHeaders = AEM_LEN_LONGRESPONSE_HEADERS + numDigits(lenEnc) + (keepAlive? 34 : 5);

	randombytes_buf(response + lenHeaders, crypto_box_NONCEBYTES);
	if (crypto_box_easy(response + lenHeaders + crypto_box_NONCEBYTES, data, lenData, response + lenHeaders, upk, ssk) == 0) {
		lenResponse = lenHeaders + lenEnc;
	} else {
		shortResponse(NULL, AEM_API_ERR_ENC_RESP);
	}
}

static unsigned char getUserLevel(const unsigned char * const pubkey) {
	const int sock = accountSocket(AEM_API_INTERNAL_LEVEL, pubkey, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return 0;

	unsigned char ret;
	recv(sock, &ret, 1, 0);
	close(sock);
	return ret;
}

static void systemMessage(unsigned char toPubKey[crypto_box_PUBLICKEYBYTES], const unsigned char * const msgContent, const size_t lenMsgContent) {
	// Create message
	const uint32_t ts = (uint32_t)time(NULL);

	const size_t lenContent = 6 + lenMsgContent;
	unsigned char content[lenContent];
	content[0] = msg_getPadAmount(lenContent) | 16; // 16=IntMsg
	memcpy(content + 1, &ts, 4);
	content[5] = 192; // InfoByte: System
	memcpy(content + 6, msgContent, lenMsgContent);

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(toPubKey, content, lenContent, &lenEnc);

	// Store message
	unsigned char sockMsg[2 + crypto_box_PUBLICKEYBYTES];
	const uint16_t u = (lenEnc / 16) - AEM_MSG_MINBLOCKS;
	memcpy(sockMsg, &u, 2);
	memcpy(sockMsg + 2, toPubKey, crypto_box_PUBLICKEYBYTES);

	const int sock = storageSocket(AEM_API_MESSAGE_UPLOAD, sockMsg, 2 + crypto_box_PUBLICKEYBYTES);
	if (sock < 0) {free(enc); return;}

	const ssize_t sentBytes = send(sock, enc, lenEnc, 0);
	free(enc);

	unsigned char resp;
	if (sentBytes != (ssize_t)(lenEnc) || recv(sock, &resp, 1, 0) != 1 || resp != AEM_INTERNAL_RESPONSE_OK) {syslog(LOG_ERR, "Failed communicating with Storage"); close(sock); return;}
	close(sock);
}

static void account_browse(void) {
	if (lenDecrypted != 1) return shortResponse(NULL, AEM_API_ERR_FORMAT);
	if (getUserLevel(upk) != AEM_USERLEVEL_MAX) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);

	const int sock = accountSocket(AEM_API_ACCOUNT_BROWSE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	int userCount;
	if (recv(sock, &userCount, sizeof(int), 0) != sizeof(int)) {close(sock); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}
	if (userCount < 1 || userCount >= UINT16_MAX) {close(sock); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}
	if (userCount == 1) {close(sock); return shortResponse(NULL, 0);}

	unsigned char * const clr = malloc(userCount * 35);
	if (clr == NULL) {syslog(LOG_ERR, "Failed malloc()"); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	const ssize_t lenClr = recv(sock, clr, userCount * 35, MSG_WAITALL);
	close(sock);

	if (lenClr < 10) {
		free(clr);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	longResponse(clr, lenClr);
	free(clr);
}

static void account_create(void) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) return shortResponse(NULL, AEM_API_ERR_FORMAT);
	if (getUserLevel(upk) != AEM_USERLEVEL_MAX) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);

	const int sock = accountSocket(AEM_API_ACCOUNT_CREATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	unsigned char resp = 0;
	recv(sock, &resp, 1, 0);
	close(sock);

	switch (resp) {
		case AEM_INTERNAL_RESPONSE_OK:
			systemMessage(decrypted, AEM_WELCOME, AEM_WELCOME_LEN);
			shortResponse(NULL, 0);
		break;

		case AEM_INTERNAL_RESPONSE_EXIST:
			shortResponse(NULL, AEM_API_ERR_ACCOUNT_CREATE_EXIST);
		break;

		default:
			shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}
}

static void account_delete(void) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	int sock = accountSocket(AEM_API_ACCOUNT_DELETE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	unsigned char resp = 0;
	recv(sock, &resp, 1, 0);
	close(sock);

	if (resp == AEM_INTERNAL_RESPONSE_VIOLATION) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);
	if (resp != AEM_INTERNAL_RESPONSE_OK) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	sock = storageSocket(AEM_API_INTERNAL_ERASE, decrypted, lenDecrypted);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_ACCOUNT_DELETE_NOSTORAGE);

	resp = 0;
	recv(sock, &resp, 1, 0);
	close(sock);

	shortResponse(NULL, (resp == AEM_INTERNAL_RESPONSE_OK) ? 0 : AEM_API_ERR_ACCOUNT_DELETE_NOSTORAGE);
}

static void account_update(void) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES + 1) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	const int sock = accountSocket(AEM_API_ACCOUNT_UPDATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	unsigned char resp = 0;
	if (recv(sock, &resp, 1, 0) != 1) {close(sock); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}
	close(sock);

	if (resp == AEM_INTERNAL_RESPONSE_OK) {
		systemMessage(decrypted + 1, (const unsigned char[]){'A','c','c','o','u','n','t',' ','l','e','v','e','l',' ','s','e','t',' ','t','o',' ','0' + decrypted[0],'\n','Y','o','u','r',' ','a','c','c','o','u','n','t',' ','l','e','v','e','l',' ','h','a','s',' ','b','e','e','n',' ','s','e','t',' ','t','o',' ','0' + decrypted[0],'.'}, 60);
		shortResponse(NULL, 0);
	} else if (resp == AEM_INTERNAL_RESPONSE_VIOLATION) {
		shortResponse(NULL, AEM_API_ERR_ADMINONLY);
	} else {
		shortResponse(NULL, AEM_API_ERR_FIXME);
	}
}

static void address_create(void) {
	if (lenDecrypted != 8 && (lenDecrypted != 6 || memcmp(decrypted, "SHIELD", 6) != 0)) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	const int sock = accountSocket(AEM_API_ADDRESS_CREATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed sending data to Account");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	unsigned char data[18];
	const int ret = recv(sock, data, 18, 0);
	close(sock);
	if (ret < 1) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (ret == 1) {
		if (data[0] == AEM_INTERNAL_RESPONSE_OK && lenDecrypted == 8) return shortResponse(NULL, 0); // Normal address OK
		if (data[0] == AEM_INTERNAL_RESPONSE_LIMIT) return shortResponse(NULL, AEM_API_ERR_ADDRESS_CREATE_ATLIMIT);
		if (data[0] == AEM_INTERNAL_RESPONSE_EXIST) return shortResponse(NULL, AEM_API_ERR_ADDRESS_CREATE_INUSE);
	}

	if (ret == 18 && lenDecrypted == 6) return shortResponse(data, 18); // Shield address OK

	// Error
	syslog(LOG_ERR, "Failed receiving data from Account");
	shortResponse(NULL, AEM_API_ERR_INTERNAL);
}

static unsigned char accountMessage(const unsigned char command) {
	const int sock = accountSocket(command, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return AEM_INTERNAL_RESPONSE_NONE;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return AEM_INTERNAL_RESPONSE_NONE;
	}

	unsigned char resp = AEM_INTERNAL_RESPONSE_NONE;
	if (recv(sock, &resp, 1, 0) != 1) syslog(LOG_ERR, "Failed communicating with Account");
	close(sock);
	return resp;
}

static void address_delete(void) {
	if (lenDecrypted != 8) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	const unsigned char resp = accountMessage(AEM_API_ADDRESS_DELETE);
	if (resp == AEM_INTERNAL_RESPONSE_OK) return shortResponse(NULL, 0);
	if (resp == AEM_INTERNAL_RESPONSE_PARTIAL) return shortResponse(NULL, AEM_API_ERR_ADDRESS_DELETE_SOMEFOUND);
	if (resp == AEM_INTERNAL_RESPONSE_NOTEXIST) return shortResponse(NULL, AEM_API_ERR_ADDRESS_DELETE_NONEFOUND);
	return shortResponse(NULL, AEM_API_ERR_INTERNAL);
}

static void address_lookup(void) {
	// TODO
}

static void address_update(void) {
	if (lenDecrypted % 9 != 0) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	const unsigned char resp = accountMessage(AEM_API_ADDRESS_UPDATE);
	if (resp == AEM_INTERNAL_RESPONSE_OK) return shortResponse(NULL, 0);
	if (resp == AEM_INTERNAL_RESPONSE_PARTIAL) return shortResponse(NULL, AEM_API_ERR_ADDRESS_UPDATE_SOMEFOUND);
	if (resp == AEM_INTERNAL_RESPONSE_NOTEXIST) return shortResponse(NULL, AEM_API_ERR_ADDRESS_UPDATE_NONEFOUND);
	return shortResponse(NULL, AEM_API_ERR_INTERNAL);
}

static void message_browse(void) {
	unsigned char sockMsg[crypto_box_PUBLICKEYBYTES + 17];
	memcpy(sockMsg, upk, crypto_box_PUBLICKEYBYTES);
	if (lenDecrypted == 17) memcpy(sockMsg + crypto_box_PUBLICKEYBYTES, decrypted, lenDecrypted);
	else if (lenDecrypted != 1) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	// Data to boxed
	unsigned char * const clr = sodium_malloc(AEM_MAXLEN_MSGDATA + 9999);
	if (clr == NULL) {syslog(LOG_ERR, "Failed allocation"); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	ssize_t lenClr = 0;

	// User info, if requested
	if (decrypted[0] & AEM_FLAG_UINFO) {
		const int sock = accountSocket(AEM_API_INTERNAL_UINFO, upk, crypto_box_PUBLICKEYBYTES);
		if (sock < 0) {sodium_free(clr); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

		const ssize_t rbytes = recv(sock, clr, 9000, MSG_WAITALL);
		close(sock);

		if (rbytes < 5) {
			syslog(LOG_ERR, "Failed receiving data from Account");
			sodium_free(clr);
			return shortResponse(NULL, AEM_API_ERR_INTERNAL);
		}

		lenClr += rbytes;
	}

	// Message data
	const int sock = storageSocket(AEM_API_MESSAGE_BROWSE, sockMsg, crypto_box_PUBLICKEYBYTES + ((lenDecrypted == 17) ? lenDecrypted : 0));
	if (sock < 0) {sodium_free(clr); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	const ssize_t lenRcv = recv(sock, clr + lenClr, AEM_MAXLEN_MSGDATA, MSG_WAITALL);
	close(sock);
	if (lenRcv < 1) {sodium_free(clr); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}
	lenClr += lenRcv;

	if (lenClr <= 32) {
		shortResponse(clr, lenClr);
	} else {
		longResponse(clr, lenClr);
	}

	sodium_free(clr);
}

static bool addr32OwnedByPubkey(const unsigned char * const ver_pk, const unsigned char * const ver_addr32, const bool shield) {
	unsigned char addrData[11];
	addrData[0] = shield? 'S' : 'N';
	memcpy(addrData + 1, ver_addr32, 10);

	const int sock = accountSocket(AEM_API_INTERNAL_MYADR, ver_pk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return false;

	unsigned char resp;
	const bool isOk = (
	   send(sock, addrData, 11, 0) == 11
	&& recv(sock, &resp, 1, 0) == 1
	&& resp == AEM_INTERNAL_RESPONSE_OK
	);

	close(sock);
	return isOk;
}

static int getAddr32(unsigned char target[10], const char * const src, const size_t lenSrc, bool * const isShield) {
	char addr[16];
	size_t lenAddr = 0;

	for (size_t i = 0; i < lenSrc; i++) {
		if (isalnum(src[i])) {
			if (lenAddr >= 16) return -1; // Over 16 alphanumerics
			addr[lenAddr] = src[i];
			lenAddr++;
		}
	}

	*isShield = (lenAddr == 16);
	addr32_store(target, addr, lenAddr);
	return 0;
}

static const unsigned char *cpyEmail(const unsigned char * const src, const size_t lenSrc, char * const target, const size_t min) {
	target[0] = '\0';

	const unsigned char * const lf = memchr(src, '\n', lenSrc);
	if (lf == NULL) return NULL;

	size_t len = lf - src;
	if (len < min || len > 127) return NULL;

	for (size_t i = 0; i < len; i++) {
		if (src[i] < 32 || src[i] >= 127) return NULL;
		target[i] = src[i];
	}

	target[len] = '\0';
	return src + len + 1;
}

static bool addrOwned(const char * const addr) {
	unsigned char addrFrom32[10];
	bool fromShield = false;
	if (getAddr32(addrFrom32, addr, strlen(addr), &fromShield) != 0) return false;
	return addr32OwnedByPubkey(upk, addrFrom32, fromShield);
}

static void deliveryReport_store(const unsigned char * const enc, const size_t lenEnc) {
	unsigned char sockMsg[2 + crypto_box_PUBLICKEYBYTES];
	const uint16_t u = (lenEnc / 16) - AEM_MSG_MINBLOCKS;
	memcpy(sockMsg, &u, 2);
	memcpy(sockMsg + 2, upk, crypto_box_PUBLICKEYBYTES);

	const int sock = storageSocket(AEM_API_MESSAGE_UPLOAD, sockMsg, 2 + crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	const ssize_t sentBytes = send(sock, enc, lenEnc, 0);
	close(sock);
	if (sentBytes != (ssize_t)(lenEnc)) {syslog(LOG_ERR, "Failed communicating with Storage"); return;}
}

static size_t deliveryReport_ext(const struct outEmail * const email, const struct outInfo * const info, unsigned char ** const output, unsigned char * msgId) {
	const size_t lenSubject  = strlen(email->subject);
	const size_t lenAddressT = strlen(email->addrTo);
	const size_t lenAddressF = strlen(email->addrFrom);
	const size_t lenMxDomain = strlen(email->mxDomain);
	const size_t lenGreeting = strlen(info->greeting);
	const size_t lenBody     = strlen(email->body);

	const size_t lenOutput = 19 + lenAddressT + lenAddressF + lenMxDomain + lenGreeting + lenSubject + lenBody;
	*output = sodium_malloc(lenOutput);
	if (*output == NULL) {syslog(LOG_ERR, "Failed allocation"); return 0;}

	const uint16_t cs16 = (info->tls_ciphersuite > UINT16_MAX || info->tls_ciphersuite < 0) ? 1 : info->tls_ciphersuite;

	(*output)[0] = msg_getPadAmount(lenOutput) | 48; // 48=OutMsg
	memcpy((*output) + 1, &(info->timestamp), 4);
	(*output)[5] = lenSubject;

	memcpy((*output) + 6, &(email->ip), 4);
	memcpy((*output) + 10, &cs16, 2);
	(*output)[12] = ((info->tls_version & 7) << 5) | 0 /*attachments*/;
	(*output)[13] = email->cc[0];
	(*output)[14] = email->cc[1];
	(*output)[15] = lenAddressT;
	(*output)[16] = lenAddressF;
	(*output)[17] = lenMxDomain;
	(*output)[18] = lenGreeting;

	size_t offset = 19;
	memcpy((*output) + offset, email->addrTo,   lenAddressT); offset += lenAddressT;
	memcpy((*output) + offset, email->addrFrom, lenAddressF); offset += lenAddressF;
	memcpy((*output) + offset, email->mxDomain, lenMxDomain); offset += lenMxDomain;
	memcpy((*output) + offset, info->greeting,  lenGreeting); offset += lenGreeting;
	memcpy((*output) + offset, email->subject,  lenSubject);  offset += lenSubject;
	memcpy((*output) + offset, email->body,     lenBody);

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(upk, *output, lenOutput, &lenEnc);
	if (enc == NULL) {
		sodium_free(*output);
		syslog(LOG_ERR, "Failed creating encrypted message");
		return 0;
	}

	deliveryReport_store(enc, lenEnc);
	memcpy(msgId, enc, 16);
	free(enc);
	return lenOutput;
}

static size_t deliveryReport_int(const unsigned char * const recvPubKey, const unsigned char * const ts, const unsigned char * const fromAddr32, const unsigned char * const toAddr32, const unsigned char * const subj, const size_t lenSubj, const unsigned char * const body, const size_t lenBody, const bool isEncrypted, const unsigned char infoByte, unsigned char ** const output, unsigned char * const msgId) {
	const size_t lenOutput = (isEncrypted? (27 + crypto_kx_PUBLICKEYBYTES) : 27) + lenSubj + lenBody;
	*output = sodium_malloc(lenOutput);
	if (*output == NULL) {syslog(LOG_ERR, "Failed allocation"); return 0;}

	(*output)[0] = msg_getPadAmount(lenOutput) | 48; // 48=OutMsg (DeliveryReport)
	memcpy((*output) + 1, ts, 4);
	(*output)[5] = lenSubj | 128; // 128 = IntMsg
	(*output)[6] = infoByte;
	memcpy((*output) + 7, fromAddr32, 10);
	memcpy((*output) + 17, toAddr32, 10);

	if (isEncrypted) {
		memcpy((*output) + 27, recvPubKey, crypto_kx_PUBLICKEYBYTES);
		memcpy((*output) + 27 + crypto_kx_PUBLICKEYBYTES, subj, lenSubj);
		memcpy((*output) + 27 + crypto_kx_PUBLICKEYBYTES + lenSubj, body, lenBody);
	} else {
		memcpy((*output) + 27, subj, lenSubj);
		memcpy((*output) + 27 + lenSubj, body, lenBody);
	}

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(upk, *output, lenOutput, &lenEnc);
	if (enc == NULL) {syslog(LOG_ERR, "Failed creating encrypted message"); return 0;}
	memcpy(msgId, enc, 16);
	deliveryReport_store(enc, lenEnc);
	free(enc);
	return lenOutput;
}

static bool isValidFrom(const char * const src) { // Only allow sending from valid, reasonably normal looking addresses
	const size_t len = strlen(src);
	if (len > 63) return false;

	for (size_t i = 0; i < len; i++) {
		if (isalnum(src[i])
		|| src[i] == '+'
		|| src[i] == '-'
		|| src[i] == '='
		|| src[i] == '_'
		) continue;

		if (i == 0 || i == len - 1 || src[i] != '.' || src[i - 1] == '.') return false; // dots allowed, but not at start or end, and not after each other
	}

	return true;
}

static void message_create_ext(void) {
	const int userLevel = getUserLevel(upk);
	if (userLevel < AEM_MINLEVEL_SENDEMAIL) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_MINLEVEL);

	struct outEmail email;
	bzero(&email, sizeof(email));

	struct outInfo info;
	bzero(&info, sizeof(info));
	info.timestamp = (uint32_t)time(NULL);

	// Address From
	const unsigned char *p = decrypted + 1;
	const unsigned char * const end = decrypted + lenDecrypted;
	p = cpyEmail(p, end - p, email.addrFrom, 1); if (p == NULL || !addrOwned(email.addrFrom)) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_FORMAT_FROM);
	p = cpyEmail(p, end - p, email.addrTo,   6); if (p == NULL) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_FORMAT_TO);
	p = cpyEmail(p, end - p, email.replyId,  0); if (p == NULL) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_FORMAT_REPLYID);
	p = cpyEmail(p, end - p, email.subject,  3); if (p == NULL) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_FORMAT_SUBJECT);

	if (strchr(email.replyId, ' ') != NULL) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_INVALID_REPLYID);
	if (!isValidFrom(email.addrFrom))       return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_INVALID_FROM);
	if (!isValidEmail(email.addrTo))        return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_INVALID_TO);

	// Body
	const size_t lenBody = end - p;
	if (lenBody < 15 || lenBody > 99999)          return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_BODY_SIZE);
	if (!isValidUtf8((unsigned char*)p, lenBody)) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_BODY_UTF8);

	email.body = malloc(lenBody + 1000);
	if (email.body == NULL) {syslog(LOG_ERR, "Failed allocation"); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	email.lenBody = 0;
	size_t lineLength = 0;
	for (size_t copied = 0; copied < lenBody; copied++) {
		if (p[copied] == '\n') { // Linebreak
			memcpy(email.body + email.lenBody, "\r\n", 2);
			email.lenBody += 2;
			lineLength = 0;
		} else if ((p[copied] < 32 && p[copied] != '\t') || p[copied] == 127) { // Control characters
			free(email.body);
			return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_BODY_CONTROL);
		} else if (p[copied] > 127) { // UTF-8
			// TODO - Forbid for now
			free(email.body);
			return shortResponse(NULL, AEM_API_ERR_TODO);
		} else { // ASCII
			lineLength++;
			if (lineLength > 998) {
				free(email.body);
				return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_LINE_TOOLONG);
			}

			email.body[email.lenBody] = p[copied];
			email.lenBody++;
		}

		if (email.lenBody > lenBody + 950) {
			free(email.body);
			return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_BODY_FORMAT);
		}
	}

	while (email.lenBody > 0 && isspace(email.body[email.lenBody - 1]))
		email.lenBody--;

	memcpy(email.body + email.lenBody, "\r\n", 2);
	email.lenBody += 2;

	if (email.lenBody < 15) {
		free(email.body);
		return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_BODY_TOOSHORT);
	}

	// Domain
	const char * const emailDomain = strchr(email.addrTo + 1, '@');
	if (emailDomain == NULL || strlen(emailDomain) < 5) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_TODOMAIN); // 5=@a.bc

	const int sock = enquirySocket(AEM_ENQUIRY_MX, (unsigned char*)emailDomain + 1, strlen(emailDomain) - 1);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	int lenMxDomain = 0;
	email.ip = 0;
	if (
	   recv(sock, &(email.ip), 4, 0) != 4
	|| email.ip <= 1
	|| recv(sock, email.cc, 2, 0) != 2
	|| recv(sock, &lenMxDomain, sizeof(int), 0) != sizeof(int)
	|| lenMxDomain < 4
	|| lenMxDomain > 255
	|| recv(sock, email.mxDomain, lenMxDomain, 0) != lenMxDomain
	) {
		close(sock);
		free(email.body);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	email.mxDomain[lenMxDomain] = '\0';
	close(sock);

	// Deliver
	const unsigned char ret = sendMail(upk, userLevel, &email, &info);

	if (ret == 0) {
		unsigned char msgId[16];
		unsigned char *report = NULL;
		const size_t lenReport = deliveryReport_ext(&email, &info, &report, msgId);
		if (lenReport == 0 || report == NULL) {
			return shortResponse(NULL, 0); // TODO
		}

		const size_t lenFinal = 16 + lenReport;
		unsigned char * const final = sodium_malloc(lenFinal);
		if (final == NULL) {sodium_free(report); return;}
		memcpy(final, msgId, 16);
		memcpy(final + 16, report, lenReport);
		sodium_free(report);

		longResponse(final, lenFinal);
		sodium_free(final);
	} else if (ret > 32) {
		shortResponse(NULL, ret);
	} else {
		shortResponse(NULL, AEM_API_ERR_FIXME);
	}

	free(email.body);
}

static bool ts_valid(const unsigned char * const ts_sender) {
	const int ts_our = (int)time(NULL);

	uint32_t ts_sender_u;
	memcpy(&ts_sender_u, ts_sender, 4);

	return abs((int)ts_sender_u - ts_our) < 10;
}

static void message_create_int(void) {
	const unsigned char infoByte = (decrypted[0] & 76) | (getUserLevel(upk) & 3); // 76=64+8+4
	const bool isEncrypted = (infoByte & 64) > 0;
	const bool fromShield  = (infoByte &  8) > 0;
	const bool toShield    = (infoByte &  4) > 0;

	if (lenDecrypted < (isEncrypted? 106 : 96)) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_TOOSHORT); // 1+10+10+32+1 = 54; 177-48-64-5=60; 60-54=6; Non-E2EE: 54+6=60; E2EE (MAC): 54+16 = 70; +36 (pubkey/ts): 96/106

	unsigned char ts_sender[4];
	if (isEncrypted) {
		memcpy(ts_sender, decrypted + 1 + crypto_kx_PUBLICKEYBYTES, 4);
		if (!ts_valid(ts_sender)) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_TS_INVALID);
	} else {
		const uint32_t ts = (uint32_t)time(NULL);
		memcpy(ts_sender, &ts, 4);
	}

	unsigned char * const msgData = decrypted + crypto_kx_PUBLICKEYBYTES + 5;
	const size_t lenData = lenDecrypted - crypto_kx_PUBLICKEYBYTES - 5;

	const unsigned char lenSubj = msgData[20 + crypto_kx_PUBLICKEYBYTES];
	if (lenSubj > 127) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_SUBJECT_SIZE);

	const unsigned char * const fromAddr32 = msgData;
	const unsigned char * const toAddr32   = msgData + 10;

	if (!addr32OwnedByPubkey(upk, fromAddr32, fromShield)) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_ADDR_NOTOWN);

	// Get receiver's pubkey
	int sock = accountSocket(AEM_API_INTERNAL_ADRPK, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	unsigned char buf[11];
	buf[0] = toShield? 'S' : 'N';
	memcpy(buf + 1, toAddr32, 10);
	if (send(sock, buf, 11, 0) != 11) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	unsigned char toPubKey[crypto_box_PUBLICKEYBYTES];
	if (recv(sock, toPubKey, crypto_box_PUBLICKEYBYTES, 0) != crypto_box_PUBLICKEYBYTES) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	close(sock);

	if (memcmp(toPubKey, (unsigned char[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 32) == 0) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_TO_NOTACCEPT);
	if (memcmp(toPubKey, upk, crypto_box_PUBLICKEYBYTES) == 0) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_TO_SELF); // Forbid messaging oneself (pointless; not designed for it)

	// Create message
	const size_t lenContent = 6 + lenData;
	unsigned char content[lenContent];
	content[0] = msg_getPadAmount(lenContent) | 16; // 16=IntMsg
	memcpy(content + 1, ts_sender, 4);
	content[5] = infoByte;
	memcpy(content + 6, msgData, lenData);

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(toPubKey, content, lenContent, &lenEnc);
	sodium_memzero(content, lenContent);
	if (enc == NULL) {
		syslog(LOG_ERR, "Failed creating encrypted message");
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	// Store message
	unsigned char sockMsg[2 + crypto_box_PUBLICKEYBYTES];
	const uint16_t u = (lenEnc / 16) - AEM_MSG_MINBLOCKS;
	memcpy(sockMsg, &u, 2);
	memcpy(sockMsg + 2, toPubKey, crypto_box_PUBLICKEYBYTES);

	sock = storageSocket(AEM_API_MESSAGE_UPLOAD, sockMsg, 2 + crypto_box_PUBLICKEYBYTES);
	if (sock < 0) {
		free(enc);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	const ssize_t sentBytes = send(sock, enc, lenEnc, 0);
	free(enc);

	unsigned char resp;
	if (sentBytes != (ssize_t)(lenEnc) || recv(sock, &resp, 1, 0) != 1 || resp != AEM_INTERNAL_RESPONSE_OK) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	close(sock);

	unsigned char msgId[16];
	unsigned char *report = NULL;
	const size_t lenReport = deliveryReport_int(decrypted + 1, ts_sender, fromAddr32, toAddr32, msgData + 21 + crypto_kx_PUBLICKEYBYTES, lenSubj, msgData + 21 + crypto_kx_PUBLICKEYBYTES + lenSubj, lenData - 21 - crypto_kx_PUBLICKEYBYTES - lenSubj, isEncrypted, infoByte, &report, msgId);
	if (lenReport == 0 || report == NULL) {
		return shortResponse(NULL, 0); // TODO
	}

	const size_t lenFinal = 16 + lenReport;
	unsigned char * const final = sodium_malloc(lenFinal);
	if (final == NULL) {sodium_free(report); return;}
	memcpy(final, msgId, 16);
	memcpy(final + 16, report, lenReport);
	sodium_free(report);

	longResponse(final, lenFinal);
	sodium_free(final);
}

static void message_create(void) {
	return ((decrypted[0]) > 127) ? message_create_ext() : message_create_int();
}

static void message_delete(void) {
	if (lenDecrypted % 16 != 0) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	const int sock = storageSocket(AEM_API_MESSAGE_DELETE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	unsigned char resp;
	if (recv(sock, &resp, 1, 0) != 1) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	close(sock);
	shortResponse(NULL, (resp == AEM_INTERNAL_RESPONSE_OK) ? 0 : AEM_API_ERR_INTERNAL);
}

static void message_public(void) {
	if (lenDecrypted < 59) return shortResponse(NULL, AEM_API_ERR_FORMAT); // 59 = 177-48-64-5-1
	if (getUserLevel(upk) != AEM_USERLEVEL_MAX) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);

	int sock = accountSocket(AEM_API_INTERNAL_PUBKS, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	int userCount;
	if (recv(sock, &userCount, sizeof(int), 0) != sizeof(int)) {close(sock); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}
	if (userCount < 1 || userCount > 65535) {syslog(LOG_WARNING, "Invalid usercount"); close(sock); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	unsigned char * const pubKeys = malloc(userCount * 32);
	if (pubKeys == NULL) {syslog(LOG_ERR, "Failed malloc()"); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	if (recv(sock, pubKeys, userCount * crypto_box_PUBLICKEYBYTES, MSG_WAITALL) != userCount * crypto_box_PUBLICKEYBYTES) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		free(pubKeys);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	close(sock);

	// Create message
	const uint32_t ts = (uint32_t)time(NULL);

	const size_t lenContent = 6 + lenDecrypted;
	unsigned char content[lenContent];
	content[0] = msg_getPadAmount(lenContent) | 16; // 16=IntMsg
	memcpy(content + 1, &ts, 4);
	content[5] = 128; // InfoByte: Public
	memcpy(content + 6, decrypted, lenDecrypted);

	unsigned char msgId[16];

	for (int i = 0; i < userCount; i++) {
		const unsigned char * const toPubKey = pubKeys + (i * crypto_box_PUBLICKEYBYTES);
		size_t lenEnc;
		unsigned char * const enc = msg_encrypt(toPubKey, content, lenContent, &lenEnc);
		if (enc == NULL) {
			syslog(LOG_ERR, "Failed creating encrypted message");
			sodium_memzero(content, lenContent);
			free(pubKeys);
			return shortResponse(NULL, AEM_API_ERR_INTERNAL);
		}

		if (memcmp(toPubKey, upk, crypto_box_PUBLICKEYBYTES) == 0) memcpy(msgId, enc, 16);

		// Store message
		const uint16_t u = (lenEnc / 16) - AEM_MSG_MINBLOCKS;
		unsigned char sockMsg[2 + crypto_box_PUBLICKEYBYTES];
		memcpy(sockMsg, &u, 2);
		memcpy(sockMsg + 2, toPubKey, crypto_box_PUBLICKEYBYTES);

		sock = storageSocket(AEM_API_MESSAGE_UPLOAD, sockMsg, 2 + crypto_box_PUBLICKEYBYTES);
		if (sock < 0) {
			free(enc);
			sodium_memzero(content, lenContent);
			free(pubKeys);
			return shortResponse(NULL, AEM_API_ERR_INTERNAL);
		}

		const ssize_t sentBytes = send(sock, enc, lenEnc, 0);
		free(enc);
		if (sentBytes != (ssize_t)(lenEnc)) {
			syslog(LOG_ERR, "Failed communicating with Storage");
			sodium_memzero(content, lenContent);
			free(pubKeys);
			close(sock);
			return shortResponse(NULL, AEM_API_ERR_INTERNAL);
		}

		unsigned char resp;
		if (recv(sock, &resp, 1, 0) != 1 || resp != AEM_INTERNAL_RESPONSE_OK) {
			syslog(LOG_ERR, "Failed communicating with Storage");
			sodium_memzero(content, lenContent);
			free(pubKeys);
			close(sock);
			return shortResponse(NULL, AEM_API_ERR_INTERNAL);
		}

		close(sock);
	}

	free(pubKeys);
	sodium_memzero(content, lenContent);
	shortResponse(msgId, 16);
}

static void message_sender(void) {
	if (lenDecrypted != 52) return shortResponse(NULL, AEM_API_ERR_FORMAT);
	if (getUserLevel(upk) != AEM_USERLEVEL_MAX) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);

	const int sock = accountSocket(AEM_API_MESSAGE_SENDER, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	int userCount;
	if (recv(sock, &userCount, sizeof(int), 0) != sizeof(int)) {close(sock); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}
	if (userCount < 1 || userCount >= UINT16_MAX) {close(sock); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	const ssize_t lenUpkList = userCount * crypto_box_PUBLICKEYBYTES;
	unsigned char * const upkList = malloc(lenUpkList);
	if (upkList == NULL) {syslog(LOG_ERR, "Failed malloc()"); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}
	const ssize_t lenRecv = recv(sock, upkList, lenUpkList, MSG_WAITALL);
	close(sock);

	if (lenRecv != lenUpkList) {free(upkList); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	uint32_t ts;
	memcpy(&ts, decrypted + 48, 4);

	char tmp[48];
	int result = -1;

	for (int i = 0; i < (lenUpkList / crypto_box_PUBLICKEYBYTES); i++) {
		genMsgId(tmp, ts, upkList + (i * crypto_box_PUBLICKEYBYTES), false);

		if (memcmp(tmp, decrypted, 48) == 0) {
			result = i;
			break;
		}
	}

	if (result == -1) {
		shortResponse(NULL, 0);
	} else {
		shortResponse(upkList + (result * crypto_box_PUBLICKEYBYTES), crypto_box_PUBLICKEYBYTES);
	}

	free(upkList);
}

static void message_upload(void) {
	const uint32_t ts = (uint32_t)time(NULL);

	unsigned char * const msg = malloc(5 + lenDecrypted);
	if (msg == NULL) {syslog(LOG_ERR, "Failed allocation"); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	msg[0] = msg_getPadAmount(5 + lenDecrypted) | 32;
	memcpy(msg + 1, &ts, 4);
	memcpy(msg + 5, decrypted, lenDecrypted);

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(upk, msg, 5 + lenDecrypted, &lenEnc);
	free(msg);
	if (enc == NULL) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	unsigned char sockMsg[2 + crypto_box_PUBLICKEYBYTES];
	const uint16_t u = (lenEnc / 16) - AEM_MSG_MINBLOCKS;
	memcpy(sockMsg, &u, 2);
	memcpy(sockMsg + 2, upk, crypto_box_PUBLICKEYBYTES);

	const int sock = storageSocket(AEM_API_MESSAGE_UPLOAD, sockMsg, 2 + crypto_box_PUBLICKEYBYTES);
	if (sock < 0) {free(enc); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	if (send(sock, enc, lenEnc, 0) != (ssize_t)lenEnc) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		close(sock);
		free(enc);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	unsigned char resp;
	if (recv(sock, &resp, 1, 0) != 1 || resp != AEM_INTERNAL_RESPONSE_OK) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		free(enc);
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	close(sock);
	shortResponse(enc, 16);
	free(enc);
}

static void private_update(void) {
	if (lenDecrypted != AEM_LEN_PRIVATE) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	const int sock = accountSocket(AEM_API_PRIVATE_UPDATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	close(sock);
	shortResponse(NULL, 0);
}

static void setting_limits(void) {
	if (lenDecrypted != 12) return shortResponse(NULL, AEM_API_ERR_FORMAT);
	if (getUserLevel(upk) != AEM_USERLEVEL_MAX) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);

	const int sock = accountSocket(AEM_API_SETTING_LIMITS, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	unsigned char resp = 0;
	recv(sock, &resp, 1, 0);
	close(sock);
	shortResponse(NULL, (resp == AEM_INTERNAL_RESPONSE_OK) ? 0 : AEM_API_ERR_INTERNAL);
}

int aem_api_prepare(const unsigned char * const sealEnc, const bool ka) {
	if (sealEnc == NULL) return AEM_INTERNAL_RESPONSE_ERR;
	keepAlive = ka;

	unsigned char sealDec[AEM_API_SEALBOX_SIZE - crypto_box_SEALBYTES];
	if (crypto_box_seal_open(sealDec, sealEnc, AEM_API_SEALBOX_SIZE, spk, ssk) != 0) return AEM_INTERNAL_RESPONSE_CRYPTOFAIL;

	postCmd = sealDec[0];
	memcpy(postNonce, sealDec + 1, crypto_box_NONCEBYTES);
	memcpy(upk, sealDec + 1 + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);

	const int sock = accountSocket(AEM_API_INTERNAL_EXIST, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return AEM_INTERNAL_RESPONSE_ERR;

	unsigned char resp = AEM_INTERNAL_RESPONSE_ERR;
	recv(sock, &resp, 1, 0);
	close(sock);
	return resp;
}

__attribute__((warn_unused_result))
int aem_api_process(const unsigned char * const box, size_t lenBox, unsigned char ** const response_p) {
	if (decrypted == NULL || box == NULL) return -1;

	sodium_mprotect_readwrite(decrypted);
	if (crypto_box_open_easy(decrypted, box, lenBox, postNonce, upk, ssk) != 0) {
		sodium_mprotect_noaccess(decrypted);
		return -1;
	}
	lenDecrypted = lenBox - crypto_box_MACBYTES;

	sodium_mprotect_readonly(decrypted);
	lenResponse = AEM_API_ERR_MISC;

	switch (postCmd) {
		case AEM_API_ACCOUNT_BROWSE: account_browse(); break;
		case AEM_API_ACCOUNT_CREATE: account_create(); break;
		case AEM_API_ACCOUNT_DELETE: account_delete(); break;
		case AEM_API_ACCOUNT_UPDATE: account_update(); break;

		case AEM_API_ADDRESS_CREATE: address_create(); break;
		case AEM_API_ADDRESS_DELETE: address_delete(); break;
		case AEM_API_ADDRESS_LOOKUP: address_lookup(); break;
		case AEM_API_ADDRESS_UPDATE: address_update(); break;

		case AEM_API_MESSAGE_BROWSE: message_browse(); break;
		case AEM_API_MESSAGE_CREATE: message_create(); break;
		case AEM_API_MESSAGE_DELETE: message_delete(); break;
		case AEM_API_MESSAGE_PUBLIC: message_public(); break;
		case AEM_API_MESSAGE_SENDER: message_sender(); break;
		case AEM_API_MESSAGE_UPLOAD: message_upload(); break;

		case AEM_API_PRIVATE_UPDATE: private_update(); break;
		case AEM_API_SETTING_LIMITS: setting_limits(); break;

		default: shortResponse(NULL, AEM_API_ERR_CMD);
	}

	clearDecrypted();
	sodium_memzero(upk, crypto_box_PUBLICKEYBYTES);

	*response_p = response;
	return lenResponse;
}
