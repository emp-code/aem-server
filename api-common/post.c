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
#include "../Common/IntCom_Client.h"
#include "../Common/ValidEmail.h"
#include "../Common/ValidUtf8.h"
#include "../Common/memeq.h"
#include "../Data/welcome.h"

#include "Error.h"
#include "MessageId.h"
#include "SendMail.h"

#include "post.h"

#define AEM_API_HTTP

struct postRequest {
	bool keepAlive;
	int postCmd;
	uint32_t lenPost;
	unsigned char nonce[crypto_box_NONCEBYTES];
	unsigned char upk[crypto_box_PUBLICKEYBYTES];
	unsigned char post[AEM_API_BOX_SIZE_MAX];
};

unsigned char *response = NULL;
int lenResponse;

static struct postRequest *req = NULL;

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

	req = sodium_malloc(sizeof(struct postRequest));
	if (req == NULL) return -1;

	response = sodium_malloc(AEM_MAXLEN_MSGDATA + AEM_MAXLEN_UINFO + 250);
	if (response == NULL) return -1;

	return 0;
}

void aem_api_free(void) {
	sodium_memzero(spk, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(ssk, crypto_box_SECRETKEYBYTES);
	sodium_memzero(sign_skey, crypto_sign_SECRETKEYBYTES);
	sodium_free(req);

	tlsFree_sendmail();
}

#include "../Common/Message.c"

static void shortResponse(const unsigned char * const data, const unsigned char lenData) {
#ifndef AEM_IS_ONION
	#define AEM_LEN_SHORTRESPONSE_HEADERS 231
#else
	#define AEM_LEN_SHORTRESPONSE_HEADERS 120
#endif

	memcpy(response, req->keepAlive?
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

	const int ret = crypto_box_easy(response + AEM_LEN_SHORTRESPONSE_HEADERS + crypto_box_NONCEBYTES, clr, 33, response + AEM_LEN_SHORTRESPONSE_HEADERS, req->upk, ssk);
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
	lenEnc, req->keepAlive ? "keep-alive\r\nKeep-Alive: timeout=30" : "close");

	const size_t lenHeaders = AEM_LEN_LONGRESPONSE_HEADERS + numDigits(lenEnc) + (req->keepAlive? 34 : 5);

	randombytes_buf(response + lenHeaders, crypto_box_NONCEBYTES);
	if (crypto_box_easy(response + lenHeaders + crypto_box_NONCEBYTES, data, lenData, response + lenHeaders, req->upk, ssk) == 0) {
		lenResponse = lenHeaders + lenEnc;
	} else {
		shortResponse(NULL, AEM_API_ERR_ENC_RESP);
	}
}

static unsigned char getUserLevel(const unsigned char * const pubkey) {
	switch (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_INTERNAL_LEVEL, pubkey, crypto_box_PUBLICKEYBYTES, NULL, 0)) {
		case -1: return 1;
		case -2: return 2;
		case -3: return 3;
	}

	return 0;
}

static void systemMessage(unsigned char toUpk[crypto_box_PUBLICKEYBYTES], const unsigned char * const msgContent, const size_t lenMsgContent) {
	// Create message
	const uint32_t ts = (uint32_t)time(NULL);

	const size_t lenContent = 6 + lenMsgContent;
	unsigned char content[lenContent];
	content[0] = msg_getPadAmount(lenContent) | 16; // 16=IntMsg
	memcpy(content + 1, &ts, 4);
	content[5] = 192; // InfoByte: System
	memcpy(content + 6, msgContent, lenMsgContent);

	size_t lenEnc = 0;
	unsigned char * const enc = msg_encrypt(toUpk, content, lenContent, &lenEnc);
	if (intcom(AEM_INTCOM_TYPE_STORAGE, AEM_API_MESSAGE_UPLOAD, enc, lenEnc, NULL, 0) != AEM_INTCOM_RESPONSE_OK) {syslog(LOG_WARNING, "Failed delivering system message");}
	free(enc);
}

static void account_browse(void) {
	if (req->lenPost != 1) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	unsigned char *clr = NULL;
	const int32_t lenClr = intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_ACCOUNT_BROWSE, req->upk, crypto_box_PUBLICKEYBYTES, &clr, 0);
	if (clr == NULL || lenClr < 1) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (lenClr < 10) {
		sodium_free(clr);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	longResponse(clr, lenClr);
	sodium_free(clr);
}

static void account_create(void) {
	if (req->lenPost != crypto_box_PUBLICKEYBYTES) return shortResponse(NULL, AEM_API_ERR_FORMAT);
	if (getUserLevel(req->upk) != AEM_USERLEVEL_MAX) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);

	switch (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_ACCOUNT_CREATE, req->upk, crypto_box_PUBLICKEYBYTES + req->lenPost, NULL, 0)) {
		case AEM_INTCOM_RESPONSE_OK:
			systemMessage(req->post, AEM_WELCOME, AEM_WELCOME_LEN);
			return shortResponse(NULL, 0);
		break;

		case AEM_INTCOM_RESPONSE_EXIST:
			shortResponse(NULL, AEM_API_ERR_ACCOUNT_CREATE_EXIST);
		break;

		default:
			shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}
}

static void account_delete(void) {
	if (req->lenPost != crypto_box_PUBLICKEYBYTES) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	switch (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_ACCOUNT_DELETE, req->upk, crypto_box_PUBLICKEYBYTES + req->lenPost, NULL, 0)) {
		case AEM_INTCOM_RESPONSE_OK: {
			const int32_t ret = intcom(AEM_INTCOM_TYPE_STORAGE, AEM_API_INTERNAL_ERASE, req->post, req->lenPost, NULL, 0);
			shortResponse(NULL, (ret == AEM_INTCOM_RESPONSE_OK) ? 0 : AEM_API_ERR_ACCOUNT_DELETE_NOSTORAGE);
		break;}

		case AEM_INTCOM_RESPONSE_PERM: {
			shortResponse(NULL, AEM_API_ERR_ADMINONLY);
		break;}

		default: shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}
}

static void account_update(void) {
	if (req->lenPost != crypto_box_PUBLICKEYBYTES + 1) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	switch (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_ACCOUNT_UPDATE, req->upk, crypto_box_PUBLICKEYBYTES + req->lenPost, NULL, 0)) {
		case AEM_INTCOM_RESPONSE_OK:
			systemMessage(req->post + 1, (const unsigned char[]){'A','c','c','o','u','n','t',' ','l','e','v','e','l',' ','s','e','t',' ','t','o',' ','0' + req->post[0],'\n','Y','o','u','r',' ','a','c','c','o','u','n','t',' ','l','e','v','e','l',' ','h','a','s',' ','b','e','e','n',' ','s','e','t',' ','t','o',' ','0' + req->post[0],'.'}, 60);
			shortResponse(NULL, 0);
		break;

		case AEM_INTCOM_RESPONSE_PERM:
			shortResponse(NULL, AEM_API_ERR_ADMINONLY);
			break;

		default:
			shortResponse(NULL, AEM_API_ERR_FIXME);
	}
}

static void address_create(void) {
	if (req->lenPost != 8 && (req->lenPost != 6 || !memeq(req->post, "SHIELD", 6))) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	unsigned char *resp = NULL;
	const int32_t lenResp = intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_ADDRESS_CREATE, req->upk, crypto_box_PUBLICKEYBYTES + req->lenPost, &resp, 0);

	if (lenResp == AEM_INTCOM_RESPONSE_LIMIT) return shortResponse(NULL, AEM_API_ERR_ADDRESS_CREATE_ATLIMIT);
	if (lenResp == AEM_INTCOM_RESPONSE_EXIST) return shortResponse(NULL, AEM_API_ERR_ADDRESS_CREATE_INUSE);

	if (req->lenPost == 6 && lenResp == 18) { // Shield address OK
		shortResponse(resp, 18);
		sodium_free(resp);
		return;
	}

	if (lenResp > 0) {
		sodium_free(resp);
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	shortResponse(NULL, (lenResp == AEM_INTCOM_RESPONSE_OK) ? 0 : AEM_API_ERR_INTERNAL);
}

static void address_delete(void) {
	if (req->lenPost != 8) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	switch (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_ADDRESS_DELETE, req->upk, crypto_box_PUBLICKEYBYTES + req->lenPost, NULL, 0)) {
		case AEM_INTCOM_RESPONSE_OK: return shortResponse(NULL, 0);
		case AEM_INTCOM_RESPONSE_PARTIAL: return shortResponse(NULL, AEM_API_ERR_ADDRESS_DELETE_SOMEFOUND);
		case AEM_INTCOM_RESPONSE_NOTEXIST: return shortResponse(NULL, AEM_API_ERR_ADDRESS_DELETE_NONEFOUND);
	}

	return shortResponse(NULL, AEM_API_ERR_INTERNAL);
}

static void address_lookup(void) {
	// TODO
}

static void address_update(void) {
	if (req->lenPost % 9 != 0) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	switch (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_ADDRESS_UPDATE, req->upk, crypto_box_PUBLICKEYBYTES + req->lenPost, NULL, 0)) {
		case AEM_INTCOM_RESPONSE_OK: return shortResponse(NULL, 0);
		case AEM_INTCOM_RESPONSE_PARTIAL: return shortResponse(NULL, AEM_API_ERR_ADDRESS_UPDATE_SOMEFOUND);
		case AEM_INTCOM_RESPONSE_NOTEXIST: return shortResponse(NULL, AEM_API_ERR_ADDRESS_UPDATE_NONEFOUND);
	}

	return shortResponse(NULL, AEM_API_ERR_INTERNAL);
}

static void message_browse(void) {
	unsigned char sockMsg[crypto_box_PUBLICKEYBYTES + 17];
	memcpy(sockMsg, req->upk, crypto_box_PUBLICKEYBYTES);
	if (req->lenPost == 17) memcpy(sockMsg + crypto_box_PUBLICKEYBYTES, req->post, req->lenPost);
	else if (req->lenPost != 1) return shortResponse(NULL, AEM_API_ERR_FORMAT);

	// User info, if requested
	unsigned char *usr = NULL;
	int32_t lenUsr = 0;

	if (req->post[0] & AEM_FLAG_UINFO) {
		lenUsr = intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_INTERNAL_UINFO, req->upk, crypto_box_PUBLICKEYBYTES, &usr, 0);
		if (lenUsr < 1) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

		if (lenUsr < (int32_t)AEM_MINLEN_UINFO) {
			syslog(LOG_ERR, "Invalid Account response length");
			if (usr != NULL) sodium_free(usr);
			return shortResponse(NULL, AEM_API_ERR_INTERNAL);
		}
	}

	// Message data
	unsigned char *msg = NULL;
	const int32_t lenMsg = intcom(AEM_INTCOM_TYPE_STORAGE, AEM_API_MESSAGE_BROWSE, sockMsg, crypto_box_PUBLICKEYBYTES + ((req->lenPost == 17) ? req->lenPost : 0), &msg, 0);
	if (lenMsg < 0) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	unsigned char *clr = sodium_malloc(lenUsr + lenMsg);
	if (lenUsr > 0) memcpy(clr, usr, lenUsr);
	if (lenMsg > 0) memcpy(clr + lenUsr, msg, lenMsg);
	if (usr != NULL) sodium_free(usr);
	if (msg != NULL) sodium_free(msg);

	const size_t lenClr = lenUsr + lenMsg;
	if (lenClr <= 32) {
		shortResponse(clr, lenClr);
	} else {
		longResponse(clr, lenClr);
	}

	sodium_free(clr);
}

static bool addr32OwnedByPubkey(const unsigned char * const ver_pk, const unsigned char * const ver_addr32, const bool shield) {
	unsigned char icMsg[crypto_box_PUBLICKEYBYTES + 11];
	memcpy(icMsg, ver_pk, crypto_box_PUBLICKEYBYTES);
	icMsg[crypto_box_PUBLICKEYBYTES] = shield? 'S' : 'N';
	memcpy(icMsg + crypto_box_PUBLICKEYBYTES + 1, ver_addr32, 10);

	return (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_INTERNAL_MYADR, icMsg, crypto_box_PUBLICKEYBYTES + 11, NULL, 0) == AEM_INTCOM_RESPONSE_OK);
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
	return addr32OwnedByPubkey(req->upk, addrFrom32, fromShield);
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
	unsigned char * const enc = msg_encrypt(req->upk, *output, lenOutput, &lenEnc);
	if (enc == NULL) {
		sodium_free(*output);
		syslog(LOG_ERR, "Failed creating encrypted message");
		return 0;
	}
	memcpy(msgId, enc, 16);

	intcom(AEM_INTCOM_TYPE_STORAGE, AEM_API_MESSAGE_UPLOAD, enc, lenEnc, NULL, 0);
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
	unsigned char * const enc = msg_encrypt(req->upk, *output, lenOutput, &lenEnc);
	if (enc == NULL) {syslog(LOG_ERR, "Failed creating encrypted message"); return 0;}
	memcpy(msgId, enc, 16);

	intcom(AEM_INTCOM_TYPE_STORAGE, AEM_API_MESSAGE_UPLOAD, enc, lenEnc, NULL, 0);
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
	const int userLevel = getUserLevel(req->upk);
	if (userLevel < AEM_MINLEVEL_SENDEMAIL) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_MINLEVEL);

	struct outEmail email;
	bzero(&email, sizeof(email));

	struct outInfo info;
	bzero(&info, sizeof(info));
	info.timestamp = (uint32_t)time(NULL);

	// Address From
	const unsigned char *p = req->post + 1;
	const unsigned char * const end = req->post + req->lenPost;
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
	if (emailDomain == NULL || strlen(emailDomain) < 5) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_EXT_INVALID_TO); // 5=@a.bc

	unsigned char *mx = NULL;
	const int32_t lenMx = intcom(AEM_INTCOM_TYPE_ENQUIRY, AEM_ENQUIRY_MX, (unsigned char*)emailDomain + 1, strlen(emailDomain) - 1, &mx, 0);
	if (lenMx < 0) {return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

/*
	TODO

	int lenMxDomain = 0;
	email.ip = 0;
	const int rb = recv(sock, &email.ip, 4, 0);
	if (rb == 1 && (((unsigned char*)&email)[0] == AEM_API_ERR_MESSAGE_CREATE_EXT_INVALID_TO || ((unsigned char*)&email)[0] == AEM_API_ERR_MESSAGE_CREATE_EXT_OURDOMAIN)) {
		close(sock);
		free(email.body);
		return shortResponse(NULL, ((unsigned char*)&email)[0]);
	}

	if (
	   rb != 4
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
*/

	sodium_free(mx);

	// Deliver
	const unsigned char ret = sendMail(req->upk, userLevel, &email, &info);

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
	const unsigned char infoByte = (req->post[0] & 76) | (getUserLevel(req->upk) & 3); // 76=64+8+4
	const bool isEncrypted = (infoByte & 64) > 0;
	const bool fromShield  = (infoByte &  8) > 0;
	const bool toShield    = (infoByte &  4) > 0;

	if (req->lenPost < (isEncrypted? 106 : 128)) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_TOOSHORT); // 1+10+10+32+1 = 54; 177-48-64-5=60; 60-54=6; Non-E2EE: 54+6=60; E2EE (MAC): 54+16 = 70; +36 (pubkey/ts): 96/106; +32 for non-E2EE DR

	unsigned char ts_sender[4];
	if (isEncrypted) {
		memcpy(ts_sender, req->post + 1 + crypto_kx_PUBLICKEYBYTES, 4);
		if (!ts_valid(ts_sender)) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_TS_INVALID);
	} else {
		const uint32_t ts = (uint32_t)time(NULL);
		memcpy(ts_sender, &ts, 4);
	}

	unsigned char * const msgData = req->post + crypto_kx_PUBLICKEYBYTES + 5;
	const size_t lenData = req->lenPost - crypto_kx_PUBLICKEYBYTES - 5;

	const unsigned char lenSubj = msgData[20 + crypto_kx_PUBLICKEYBYTES];
	if (lenSubj > 127) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_SUBJECT_SIZE);

	const unsigned char * const fromAddr32 = msgData;
	const unsigned char * const toAddr32   = msgData + 10;

	if (!addr32OwnedByPubkey(req->upk, fromAddr32, fromShield)) return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_ADDR_NOTOWN);

	// Get receiver's pubkey
	unsigned char icMsg[11];
	icMsg[0] = toShield? 'S' : 'N';
	memcpy(icMsg + 1, toAddr32, 10);

	unsigned char *toPubKey;
	if (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_INTERNAL_ADRPK, icMsg, 11, &toPubKey, crypto_box_PUBLICKEYBYTES) != crypto_box_PUBLICKEYBYTES) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (memeq(toPubKey, (unsigned char[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 32)) {sodium_free(toPubKey); return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_TO_NOTACCEPT);}
	if (memeq(toPubKey, req->upk, crypto_box_PUBLICKEYBYTES)) {sodium_free(toPubKey); return shortResponse(NULL, AEM_API_ERR_MESSAGE_CREATE_INT_TO_SELF);} // Forbid messaging oneself (pointless; not designed for it)

	// Create message
	const size_t lenContent = 6 + lenData;
	unsigned char content[lenContent];
	content[0] = msg_getPadAmount(lenContent) | 16; // 16=IntMsg
	memcpy(content + 1, ts_sender, 4);
	content[5] = infoByte;
	memcpy(content + 6, msgData, lenData);

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(toPubKey, content, lenContent, &lenEnc);
	sodium_free(toPubKey);
	sodium_memzero(content, lenContent);
	if (enc == NULL) {
		syslog(LOG_ERR, "Failed creating encrypted message");
		return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	// Store message
	if (intcom(AEM_INTCOM_TYPE_STORAGE, AEM_API_MESSAGE_UPLOAD, enc, lenEnc, NULL, 0) != AEM_INTCOM_RESPONSE_OK) {free(enc); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}
	free(enc);

	unsigned char msgId[16];
	unsigned char *report = NULL;
	const size_t lenReport = deliveryReport_int(req->post + 1, ts_sender, fromAddr32, toAddr32, msgData + 21 + crypto_kx_PUBLICKEYBYTES, lenSubj, msgData + 21 + crypto_kx_PUBLICKEYBYTES + lenSubj, lenData - 21 - crypto_kx_PUBLICKEYBYTES - lenSubj, isEncrypted, infoByte, &report, msgId);
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
	return ((req->post[0]) > 127) ? message_create_ext() : message_create_int();
}

static void message_delete(void) {
	if (req->lenPost % 16 != 0) return shortResponse(NULL, AEM_API_ERR_FORMAT);
	shortResponse(NULL, (intcom(AEM_INTCOM_TYPE_STORAGE, AEM_API_MESSAGE_DELETE, req->post, req->lenPost, NULL, 0) == AEM_INTCOM_RESPONSE_OK) ? 0 : AEM_API_ERR_INTERNAL);
}

static void message_public(void) {
	if (req->lenPost < 59) return shortResponse(NULL, AEM_API_ERR_FORMAT); // 59 = 177-48-64-5-1
	if (getUserLevel(req->upk) != AEM_USERLEVEL_MAX) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);

	unsigned char *upks = NULL;
	const int32_t lenUpks = intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_INTERNAL_PUBKS, req->upk, crypto_box_PUBLICKEYBYTES, &upks, 0);
	if (lenUpks < 1) return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	if (lenUpks % crypto_box_PUBLICKEYBYTES != 0) {sodium_free(upks); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	// Create message
	const uint32_t ts = (uint32_t)time(NULL);

	const size_t lenContent = 6 + req->lenPost;
	unsigned char content[lenContent];
	content[0] = msg_getPadAmount(lenContent) | 16; // 16=IntMsg
	memcpy(content + 1, &ts, 4);
	content[5] = 128; // InfoByte: Public
	memcpy(content + 6, req->post, req->lenPost);

	unsigned char msgId[16];

	for (size_t i = 0; i < (lenUpks / crypto_box_PUBLICKEYBYTES); i++) {
		const unsigned char * const toUpk = upks + (i * crypto_box_PUBLICKEYBYTES);
		size_t lenEnc;
		unsigned char * const enc = msg_encrypt(toUpk, content, lenContent, &lenEnc);
		if (enc == NULL) {
			syslog(LOG_ERR, "Failed creating encrypted message");
			sodium_memzero(content, lenContent);
			sodium_free(upks);
			return shortResponse(NULL, AEM_API_ERR_INTERNAL);
		}

		if (memeq(toUpk, req->upk, crypto_box_PUBLICKEYBYTES)) memcpy(msgId, enc, 16);

		// Store message
		if (intcom(AEM_INTCOM_TYPE_STORAGE, AEM_API_MESSAGE_UPLOAD, enc, lenEnc, NULL, 0) != AEM_INTCOM_RESPONSE_OK) {
			free(enc);
			sodium_memzero(content, lenContent);
			sodium_free(upks);
			return shortResponse(NULL, AEM_API_ERR_INTERNAL);
		}

		free(enc);
	}

	sodium_free(upks);
	sodium_memzero(content, lenContent);
	shortResponse(msgId, 16);
}

static void message_sender(void) {
	if (req->lenPost != 52) return shortResponse(NULL, AEM_API_ERR_FORMAT);
	if (getUserLevel(req->upk) != AEM_USERLEVEL_MAX) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);

	unsigned char *upks = NULL;
	const int32_t lenUpks = intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_INTERNAL_PUBKS, req->upk, crypto_box_PUBLICKEYBYTES, &upks, 0);
	if (lenUpks < 1) return shortResponse(NULL, AEM_API_ERR_INTERNAL);
	if (lenUpks % crypto_box_PUBLICKEYBYTES != 0) {sodium_free(upks); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	uint32_t ts;
	memcpy(&ts, req->post + 48, 4);

	char tmp[48];
	int result = -1;

	for (size_t i = 0; i < (lenUpks / crypto_box_PUBLICKEYBYTES); i++) {
		genMsgId(tmp, ts, upks + (i * crypto_box_PUBLICKEYBYTES), false);

		if (memeq(tmp, req->post, 48)) {
			result = i;
			break;
		}
	}

	if (result == -1) {
		shortResponse(NULL, 0);
	} else {
		shortResponse(upks + (result * crypto_box_PUBLICKEYBYTES), crypto_box_PUBLICKEYBYTES);
	}

	sodium_free(upks);
}

static void message_upload(void) {
	const uint32_t ts = (uint32_t)time(NULL);

	unsigned char * const msg = malloc(5 + req->lenPost);
	if (msg == NULL) {syslog(LOG_ERR, "Failed allocation"); return shortResponse(NULL, AEM_API_ERR_INTERNAL);}

	msg[0] = msg_getPadAmount(5 + req->lenPost) | 32;
	memcpy(msg + 1, &ts, 4);
	memcpy(msg + 5, req->post, req->lenPost);

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(req->upk, msg, 5 + req->lenPost, &lenEnc);
	free(msg);
	if (enc == NULL) return shortResponse(NULL, AEM_API_ERR_INTERNAL);

	if (intcom(AEM_INTCOM_TYPE_STORAGE, AEM_API_MESSAGE_UPLOAD, enc, lenEnc, NULL, 0) != AEM_INTCOM_RESPONSE_OK) {
		shortResponse(enc, 16);
	} else {
		shortResponse(NULL, AEM_API_ERR_INTERNAL);
	}

	free(enc);
}

static void private_update(void) {
	if (req->lenPost != AEM_LEN_PRIVATE) return shortResponse(NULL, AEM_API_ERR_FORMAT);
	shortResponse(NULL, (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_PRIVATE_UPDATE, req->upk, crypto_box_PUBLICKEYBYTES + req->lenPost, NULL, 0) == AEM_INTCOM_RESPONSE_OK) ? 0 : AEM_API_ERR_INTERNAL);
}

static void setting_limits(void) {
	if (req->lenPost != 12) return shortResponse(NULL, AEM_API_ERR_FORMAT);
	if (getUserLevel(req->upk) != AEM_USERLEVEL_MAX) return shortResponse(NULL, AEM_API_ERR_ADMINONLY);
	shortResponse(NULL, (intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_SETTING_LIMITS, req->upk, crypto_box_PUBLICKEYBYTES + req->lenPost, NULL, 0) == AEM_INTCOM_RESPONSE_OK) ? 0 : AEM_API_ERR_INTERNAL);
}

int32_t aem_api_prepare(const unsigned char * const sealEnc, const bool ka) {
	if (req == NULL || sealEnc == NULL) return AEM_INTCOM_RESPONSE_ERR;

	unsigned char sealDec[AEM_API_SEALBOX_SIZE - crypto_box_SEALBYTES];
	if (crypto_box_seal_open(sealDec, sealEnc, AEM_API_SEALBOX_SIZE, spk, ssk) != 0) return AEM_INTCOM_RESPONSE_CRYPTO;

	if (labs((long)time(NULL) - *((uint32_t*)(sealDec + 1))) > AEM_API_TIMEOUT) return AEM_INTCOM_RESPONSE_LIMIT;

	sodium_mprotect_readwrite(req);
	req->postCmd = sealDec[0];
	memcpy(req->nonce, sealDec + 1, crypto_box_NONCEBYTES);
	memcpy(req->upk, sealDec + 1 + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);
	req->keepAlive = ka;
	sodium_mprotect_readonly(req);

	return intcom(AEM_INTCOM_TYPE_ACCOUNT, AEM_API_INTERNAL_EXIST, req->upk, crypto_box_PUBLICKEYBYTES, NULL, 0);
}

__attribute__((warn_unused_result))
int aem_api_process(const unsigned char * const box, size_t lenBox, unsigned char ** const response_p) {
	if (req == NULL || box == NULL) return -1;

	sodium_mprotect_readwrite(req);
	if (crypto_box_open_easy(req->post, box, lenBox, req->nonce, req->upk, ssk) != 0) {
		sodium_memzero(req, sizeof(struct postRequest));
		sodium_mprotect_noaccess(req);
		return -1;
	}
	req->lenPost = lenBox - crypto_box_MACBYTES;
	sodium_mprotect_readonly(req);

	lenResponse = AEM_API_ERR_MISC;

	switch (req->postCmd) {
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

	sodium_mprotect_readwrite(req);
	sodium_memzero(req, sizeof(struct postRequest));
	sodium_mprotect_noaccess(req);

	*response_p = response;
	return lenResponse;
}
