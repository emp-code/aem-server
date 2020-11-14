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

#include "SendMail.h"

#include "post.h"

#define AEM_VIOLATION_ACCOUNT_CREATE 0x72436341
#define AEM_VIOLATION_ACCOUNT_DELETE 0x65446341
#define AEM_VIOLATION_ACCOUNT_UPDATE 0x70556341
#define AEM_VIOLATION_SETTING_LIMITS 0x694c6553

#define AEM_API_ERROR -1
#define AEM_API_NOCONTENT 0

static bool keepAlive;
static int postCmd;
static unsigned char postNonce[crypto_box_NONCEBYTES];

static unsigned char upk[crypto_box_PUBLICKEYBYTES];
static unsigned char *response = NULL;
static unsigned char *decrypted = NULL;
static int lenResponse = AEM_API_ERROR;
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
	sm_clearKeys();
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

static void userViolation(const int violation) {
	syslog(LOG_WARNING, "Violation");
	// ...
}

static void shortResponse(const unsigned char * const data, const int len) {
	if (len != AEM_API_ERROR && (len < 0 || len > 32)) return;

#ifndef AEM_IS_ONION
	#define AEM_LEN_SHORTRESPONSE 277
#else
	#define AEM_LEN_SHORTRESPONSE 166
#endif

	memcpy(response, keepAlive?
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
#ifndef AEM_IS_ONION
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
#endif
		"Content-Length: 73\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store, no-transform\r\n"
		"Connection: keep-alive\r\n"
		"Keep-Alive: timeout=30\r\n"
		"\r\n"
	:
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
#ifndef AEM_IS_ONION
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
#endif
		"Content-Length: 73\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store, no-transform\r\n"
		"Connection: close\r\n"
		"Padding-Ignore: abcdefghijk\r\n"
		"\r\n"
	, AEM_LEN_SHORTRESPONSE);

	randombytes_buf(response + AEM_LEN_SHORTRESPONSE, crypto_box_NONCEBYTES);

	unsigned char clr[33];
	if (len == AEM_API_ERROR) {
		memset(clr, 0xFF, 33);
	} else {
		bzero(clr, 33);
		clr[0] = len;
		if (data != NULL && len > 0) memcpy(clr + 1, data, len);
	}

	const int ret = crypto_box_easy(response + AEM_LEN_SHORTRESPONSE + crypto_box_NONCEBYTES, clr, 33, response + AEM_LEN_SHORTRESPONSE, upk, ssk);
	if (ret == 0) lenResponse = AEM_LEN_SHORTRESPONSE + 73;
}

static void account_browse(void) {
	if (lenDecrypted != 1) return;

	const int sock = accountSocket(AEM_API_ACCOUNT_BROWSE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	int userCount;
	if (recv(sock, &userCount, sizeof(int), 0) != sizeof(userCount)) {close(sock); return;}

	unsigned char * const clr = malloc(userCount * 35);
	if (clr == NULL) {syslog(LOG_ERR, "Failed malloc()"); return;}

	const ssize_t lenClr = recv(sock, clr, userCount * 35, MSG_WAITALL);
	close(sock);

	if (lenClr < 10) {free(clr); return;}

	sprintf((char*)response,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
#ifndef AEM_IS_ONION
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
#endif
		"Content-Length: %zu\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store, no-transform\r\n"
		"%s"
		"\r\n",
	lenClr + crypto_box_NONCEBYTES + crypto_box_MACBYTES, keepAlive ?
		"Connection: keep-alive\r\n"
		"Keep-Alive: timeout=30\r\n"
	:
		"Connection: close\r\n"
	);

	const size_t lenHeaders = strlen((char*)response);

	randombytes_buf(response + lenHeaders, crypto_box_NONCEBYTES);
	if (crypto_box_easy(response + lenHeaders + crypto_box_NONCEBYTES, clr, lenClr, response + lenHeaders, upk, ssk) == 0)
		lenResponse = lenHeaders + crypto_box_NONCEBYTES + crypto_box_MACBYTES + lenClr;

	free(clr);
}

static void account_create(void) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) return;

	const int sock = accountSocket(AEM_API_ACCOUNT_CREATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	unsigned char resp;
	if (recv(sock, &resp, 1, 0) != 1 || resp != AEM_ACCOUNT_RESPONSE_OK) {
		close(sock);
		return;
	} else if (resp == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(AEM_VIOLATION_ACCOUNT_CREATE);
		close(sock);
		return;
	}

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return;
	}

	if (recv(sock, &resp, 1, 0) == 1 && resp == AEM_ACCOUNT_RESPONSE_OK) {
		shortResponse(NULL, AEM_API_NOCONTENT);
	}

	close(sock);
}

static void account_delete(void) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) return;

	int sock = accountSocket(AEM_API_ACCOUNT_DELETE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return;
	}

	unsigned char resp;
	if (recv(sock, &resp, 1, 0) != 1) {
		close(sock);
		return;
	}

	if (resp == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		close(sock);
		userViolation(AEM_VIOLATION_ACCOUNT_DELETE);
//		shortResponse((unsigned char*)"Violation", 9);
		return;
	} else if (resp != AEM_ACCOUNT_RESPONSE_OK) {
		close(sock);
		return;
	}

	close(sock);
	shortResponse(NULL, AEM_API_NOCONTENT);

	sock = storageSocket(AEM_API_INTERNAL_ERASE, decrypted, lenDecrypted);
	if (sock < 0) return;
	close(sock);
}

static void account_update(void) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES + 1) return;

	const int sock = accountSocket(AEM_API_ACCOUNT_UPDATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return;
	}

	unsigned char resp;
	if (recv(sock, &resp, 1, 0) == 1) {
		if (resp == AEM_ACCOUNT_RESPONSE_VIOLATION) {
			userViolation(AEM_VIOLATION_ACCOUNT_UPDATE);
//			shortResponse((unsigned char*)"Violation", 9);
		} else if (resp == AEM_ACCOUNT_RESPONSE_OK) {
			shortResponse(NULL, AEM_API_NOCONTENT);
		}
	}

	close(sock);
}

static void address_create(void) {
	if (lenDecrypted != 8 && (lenDecrypted != 6 || memcmp(decrypted, "SHIELD", 6) != 0)) return;

	const int sock = accountSocket(AEM_API_ADDRESS_CREATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed sending data to Account");
		close(sock);
		return;
	}

	if (lenDecrypted == 8) { // Normal
		unsigned char ret;
		recv(sock, &ret, 1, 0);
		close(sock);
		if (ret == AEM_ACCOUNT_RESPONSE_OK) shortResponse(NULL, AEM_API_NOCONTENT);
		return;
	}

	// Shield
	unsigned char data[18];
	if (recv(sock, data, 18, 0) != 18) {
		syslog(LOG_ERR, "Failed receiving data from Account");
		close(sock);
		return;
	}

	close(sock);
	shortResponse(data, 18);
}

static void address_delete(void) {
	if (lenDecrypted != 8) return;

	const int sock = accountSocket(AEM_API_ADDRESS_DELETE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return;
	}

	unsigned char resp;
	if (recv(sock, &resp, 1, 0) == 1 && resp == AEM_ACCOUNT_RESPONSE_OK) {
		shortResponse(NULL, AEM_API_NOCONTENT);
	}

	close(sock);
}

static void address_lookup(void) {
	// TODO
}

static void address_update(void) {
	if (lenDecrypted % 9 != 0) return;

	const int sock = accountSocket(AEM_API_ADDRESS_UPDATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return;
	}

	close(sock);
	shortResponse(NULL, AEM_API_NOCONTENT);
}

static void message_upload(void) {
	const uint32_t ts = (uint32_t)time(NULL);

	unsigned char * const msg = malloc(5 + lenDecrypted);
	if (msg == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

	msg[0] = msg_getPadAmount(5 + lenDecrypted) | 32;
	memcpy(msg + 1, &ts, 4);
	memcpy(msg + 5, decrypted, lenDecrypted);

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(upk, msg, 5 + lenDecrypted, &lenEnc);
	free(msg);
	if (enc == NULL) return;

	unsigned char sockMsg[2 + crypto_box_PUBLICKEYBYTES];
	const uint16_t u = (lenEnc / 16) - AEM_MSG_MINBLOCKS;
	memcpy(sockMsg, &u, 2);
	memcpy(sockMsg + 2, upk, crypto_box_PUBLICKEYBYTES);

	const int sock = storageSocket(AEM_API_MESSAGE_UPLOAD, sockMsg, 2 + crypto_box_PUBLICKEYBYTES);
	if (sock < 0) {free(enc); return;}

	const ssize_t sentBytes = send(sock, enc, lenEnc, 0);
	close(sock);
	if (sentBytes != (ssize_t)lenEnc) {syslog(LOG_ERR, "Failed communicating with Storage"); free(enc); return;}

	shortResponse(enc, 16);
	free(enc);
}

static void message_browse(void) {
	unsigned char sockMsg[crypto_box_PUBLICKEYBYTES + 17];
	memcpy(sockMsg, upk, crypto_box_PUBLICKEYBYTES);

	if (lenDecrypted == 17)
		memcpy(sockMsg + crypto_box_PUBLICKEYBYTES, decrypted, lenDecrypted);
	else if (lenDecrypted != 1) return;

	// Data to boxed
	unsigned char * const clr = sodium_malloc(AEM_MAXLEN_MSGDATA + 9999);
	if (clr == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

	ssize_t lenClr = 0;

	// User info, if requested
	if (decrypted[0] & AEM_FLAG_UINFO) {
		const int sock = accountSocket(AEM_API_INTERNAL_UINFO, upk, crypto_box_PUBLICKEYBYTES);
		if (sock < 0) {sodium_free(clr); return;}

		const ssize_t rbytes = recv(sock, clr, 9000, MSG_WAITALL);
		close(sock);

		if (rbytes < 5) {
			syslog(LOG_ERR, "Failed receiving data from Account");
			sodium_free(clr);
			return;
		}

		lenClr += rbytes;
	}

	// Message data
	const int sock = storageSocket(AEM_API_MESSAGE_BROWSE, sockMsg, crypto_box_PUBLICKEYBYTES + ((lenDecrypted == 17) ? lenDecrypted : 0));
	if (sock < 0) {sodium_free(clr); return;}

	const ssize_t lenRcv = recv(sock, clr + lenClr, AEM_MAXLEN_MSGDATA, MSG_WAITALL);
	close(sock);
	if (lenRcv < 1) {sodium_free(clr); return;}
	lenClr += lenRcv;

	const char * const kaStr = keepAlive ? "Connection: keep-alive\r\nKeep-Alive: timeout=30\r\n" : "";

	// Preapre and send response
	sprintf((char*)response,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
#ifndef AEM_IS_ONION
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
#endif
		"Content-Length: %zd\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"%s"
		"\r\n"
	, crypto_box_NONCEBYTES + crypto_box_MACBYTES + lenClr, kaStr);
	const size_t lenHeaders = strlen((char*)response);

	randombytes_buf(response + lenHeaders, crypto_box_NONCEBYTES);
	if (crypto_box_easy(response + lenHeaders + crypto_box_NONCEBYTES, clr, lenClr, response + lenHeaders, upk, ssk) != 0) {sodium_free(clr); return;}
	sodium_free(clr);

	lenResponse = lenHeaders + crypto_box_NONCEBYTES + crypto_box_MACBYTES + lenClr;
}

static bool addr32OwnedByPubkey(const unsigned char * const ver_pk, const unsigned char * const ver_addr32, const bool shield) {
	unsigned char addrData[11];
	addrData[0] = shield? 'S' : 'N';
	memcpy(addrData + 1, ver_addr32, 10);

	const int sock = accountSocket(AEM_API_ADDRESS_LOOKUP, ver_pk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return false;

	unsigned char answer;
	if (send(sock, addrData, 11, 0) != 11) {close(sock); return false;}
	if (recv(sock, &answer, 1, 0) != 1) {close(sock); return false;}
	close(sock);

	return (answer == 0x01);
}

static unsigned char getUserLevel(const unsigned char * const pubkey) {
	const int sock = accountSocket(AEM_API_INTERNAL_LEVEL, pubkey, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return 0;

	unsigned char ret;
	recv(sock, &ret, 1, 0);
	close(sock);
	return ret;
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
	if (len < min || len > 255) return NULL;

	for (size_t i = 0; i < len; i++) {
		if (src[i] < 32 || src[i] == 127) return NULL;
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

static void deliveryReport_ext(const struct outEmail * const email, const struct outInfo * const info) {
	const size_t lenSubject  = strlen(email->subject);
	const size_t lenAddressT = strlen(email->addrTo);
	const size_t lenAddressF = strlen(email->addrFrom);
	const size_t lenMxDomain = strlen(email->mxDomain);
	const size_t lenGreeting = strlen(info->greeting);
	const size_t lenBody     = strlen(email->body);

	const size_t lenContent = 18 + lenAddressT + lenAddressF + lenMxDomain + lenGreeting + lenSubject + lenBody;
	unsigned char * const content = sodium_malloc(lenContent);
	if (content == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

	const uint16_t cs16 = (info->tls_ciphersuite > UINT16_MAX || info->tls_ciphersuite < 0) ? 1 : info->tls_ciphersuite;

	content[0] = msg_getPadAmount(lenContent) | 48; // 48=OutMsg
	memcpy(content + 1, &(info->timestamp), 4);
	content[5] = lenSubject;

	memcpy(content + 6, &(email->ip), 4);
	memcpy(content + 10, &cs16, 2);
	content[12] = ((info->tls_version & 7) << 5) | 0 /*attachments*/;
	content[13] = info->tls_info;
	content[14] = lenAddressT;
	content[15] = lenAddressF;
	content[16] = lenMxDomain;
	content[17] = lenGreeting;

	size_t offset = 18;
	memcpy(content + offset, email->addrTo,   lenAddressT); offset += lenAddressT;
	memcpy(content + offset, email->addrFrom, lenAddressF); offset += lenAddressF;
	memcpy(content + offset, email->mxDomain, lenMxDomain); offset += lenMxDomain;
	memcpy(content + offset, info->greeting,  lenGreeting); offset += lenGreeting;
	memcpy(content + offset, email->subject,  lenSubject);  offset += lenSubject;
	memcpy(content + offset, email->body,     lenBody);

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(upk, content, lenContent, &lenEnc);
	sodium_free(content);
	if (enc == NULL) {
		syslog(LOG_ERR, "Failed creating encrypted message");
		return;
	}

	deliveryReport_store(enc, lenEnc);
	free(enc);
}

static void deliveryReport_int(const unsigned char * const recvPubKey, const unsigned char * const ts, const unsigned char * const fromAddr32, const unsigned char * const toAddr32, const unsigned char * const subj, const size_t lenSubj, const unsigned char * const body, const size_t lenBody, const bool isEncrypted, const unsigned char infoByte) {
	const size_t lenContent = (isEncrypted? (27 + crypto_kx_PUBLICKEYBYTES) : 27) + lenSubj + lenBody;
	unsigned char * const content = sodium_malloc(lenContent);
	if (content == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

	content[0] = msg_getPadAmount(lenContent) | 48; // 48=OutMsg (DeliveryReport)
	memcpy(content + 1, ts, 4);
	content[5] = lenSubj | 128; // 128 = IntMsg
	content[6] = infoByte;
	memcpy(content + 7, fromAddr32, 10);
	memcpy(content + 17, toAddr32, 10);

	if (isEncrypted) {
		memcpy(content + 27, recvPubKey, crypto_kx_PUBLICKEYBYTES);
		memcpy(content + 27 + crypto_kx_PUBLICKEYBYTES, subj, lenSubj);
		memcpy(content + 27 + crypto_kx_PUBLICKEYBYTES + lenSubj, body, lenBody);
	} else {
		memcpy(content + 27, subj, lenSubj);
		memcpy(content + 27 + lenSubj, body, lenBody);
	}

	size_t lenEnc;
	unsigned char * const enc = msg_encrypt(upk, content, lenContent, &lenEnc);
	sodium_free(content);
	if (enc == NULL) {
		syslog(LOG_ERR, "Failed creating encrypted message");
		return;
	}

	deliveryReport_store(enc, lenEnc);
	free(enc);
}

static bool isValidFrom(const char * const src) { // Only allow sending from valid, reasonably normal looking addresses
	const size_t len = strlen(src);
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
	if ((userLevel & 3) < AEM_MINLEVEL_SENDEMAIL) return;

	struct outEmail email;
	bzero(&email, sizeof(email));

	struct outInfo info;
	bzero(&info, sizeof(info));
	info.timestamp = (uint32_t)time(NULL);

	// Address From
	const unsigned char *p = decrypted + 1;
	const unsigned char * const end = decrypted + lenDecrypted;
	p = cpyEmail(p, end - p, email.addrFrom, 1); if (p == NULL || !addrOwned(email.addrFrom)) return;
	p = cpyEmail(p, end - p, email.addrTo,   6); if (p == NULL) return;
	p = cpyEmail(p, end - p, email.replyId,  0); if (p == NULL) return;
	p = cpyEmail(p, end - p, email.subject,  3); if (p == NULL) return;

	if (strchr(email.replyId, ' ') != NULL) return;
	if (!isValidFrom(email.addrFrom)) return;
	if (!isValidEmail(email.addrTo)) return;

	// Body
	const size_t lenBody = end - p;
	if (lenBody < 15) return;
	email.body = malloc(lenBody + 1000);
	if (email.body == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

	size_t lenEb = 0;
	for (size_t copied = 0; copied < lenBody; copied++) {
		if (p[copied] == '\n') { // Linebreak
			memcpy(email.body + lenEb, "\r\n", 2);
			lenEb += 2;
		} else if ((p[copied] < 32 && p[copied] != '\t') || p[copied] == 127) { // Control characters
			free(email.body);
			return;
		} else if (p[copied] > 127) { // UTF-8
			// TODO - Forbid for now
			free(email.body);
			return;
		} else { // ASCII
			email.body[lenEb] = p[copied];
			lenEb++;
		}

		if (lenEb > lenBody + 950) {free(email.body); return;}
	}
	memcpy(email.body + lenEb, "\r\n\0", 3);

	if (!isValidUtf8((unsigned char*)email.body, lenEb)) {free(email.body); return;}

	// MxDomain
	char * const mxDomain = strchr(email.addrTo + 1, '@');
	if (mxDomain == NULL || strlen(mxDomain) < 4) return; // a.bc
	strcpy(email.mxDomain, mxDomain + 1);

	const int sock = enquirySocket(AEM_DNS_LOOKUP, (unsigned char*)(email.mxDomain), strlen(email.mxDomain));
	if (sock < 0) return;

	email.ip = 0;
	recv(sock, &(email.ip), 4, 0);
	close(sock);
	if (email.ip == 0) {
		unsigned char x[32]; // Errcode + max 31 bytes
		x[0] = UINT8_MAX;
		shortResponse(x, 1);
		return;
	}

	// Deliver
	const unsigned char ret = sendMail(upk, userLevel, &email, &info);
	deliveryReport_ext(&email, &info);

	if (ret == 0) {
		shortResponse(NULL, AEM_API_NOCONTENT);
	} else {
		unsigned char x[32]; // Errcode + max 31 bytes
		x[0] = ret;
		shortResponse(x, 1);
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
	const unsigned char infoByte = (decrypted[0] & 28) | (getUserLevel(upk) & 3); // 28=16+8+4
	const bool isEncrypted = (infoByte & 16) > 0;
	const bool fromShield  = (infoByte &  8) > 0;
	const bool toShield    = (infoByte &  4) > 0;

	if (lenDecrypted < (isEncrypted? 96 : 128)) return; // Minimum message size based on AEM_MSG_MINBLOCKS

	unsigned char ts_sender[4];
	if (isEncrypted) {
		memcpy(ts_sender, decrypted + 1 + crypto_kx_PUBLICKEYBYTES, 4);
		if (!ts_valid(ts_sender)) return;
	} else {
		const uint32_t ts = (uint32_t)time(NULL);
		memcpy(ts_sender, &ts, 4);
	}

	unsigned char * const msgData = decrypted + crypto_kx_PUBLICKEYBYTES + 5;
	const size_t lenData = lenDecrypted - crypto_kx_PUBLICKEYBYTES - 5;

	const unsigned char lenSubj = msgData[20 + crypto_kx_PUBLICKEYBYTES];
	if (lenSubj > 127) return;

	const unsigned char * const fromAddr32 = msgData;
	const unsigned char * const toAddr32   = msgData + 10;

	if (!addr32OwnedByPubkey(upk, fromAddr32, fromShield)) return;

	// Get receiver's pubkey
	int sock = accountSocket(AEM_API_INTERNAL_PBKEY, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	unsigned char buf[11];
	buf[0] = toShield? 'S' : 'N';
	memcpy(buf + 1, toAddr32, 10);
	if (send(sock, buf, 11, 0) != 11) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return;
	}

	unsigned char toPubKey[crypto_box_PUBLICKEYBYTES];
	if (recv(sock, toPubKey, crypto_box_PUBLICKEYBYTES, 0) != crypto_box_PUBLICKEYBYTES) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return;
	}

	close(sock);

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
	if (enc == NULL) {syslog(LOG_ERR, "Failed creating encrypted message"); return;}

	// Store message
	unsigned char sockMsg[2 + crypto_box_PUBLICKEYBYTES];
	const uint16_t u = (lenEnc / 16) - AEM_MSG_MINBLOCKS;
	memcpy(sockMsg, &u, 2);
	memcpy(sockMsg + 2, toPubKey, crypto_box_PUBLICKEYBYTES);

	sock = storageSocket(AEM_API_MESSAGE_UPLOAD, sockMsg, 2 + crypto_box_PUBLICKEYBYTES);
	if (sock < 0) {free(enc); return;}

	const ssize_t sentBytes = send(sock, enc, lenEnc, 0);
	free(enc);
	close(sock);
	if (sentBytes != (ssize_t)(lenEnc)) {syslog(LOG_ERR, "Failed communicating with Storage"); return;}

	deliveryReport_int(decrypted + 1, ts_sender, fromAddr32, toAddr32, msgData + 21 + crypto_kx_PUBLICKEYBYTES, lenSubj, msgData + 21 + crypto_kx_PUBLICKEYBYTES + lenSubj, lenData - 21 - crypto_kx_PUBLICKEYBYTES - lenSubj, isEncrypted, infoByte);

	shortResponse(NULL, AEM_API_NOCONTENT);
}

static void message_create(void) {
	return ((decrypted[0]) > 127) ? message_create_ext() : message_create_int();
}

static void message_delete(void) {
	if (lenDecrypted % 16 != 0) return;

	const int sock = storageSocket(AEM_API_MESSAGE_DELETE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		close(sock);
		return;
	}

	close(sock);
	shortResponse(NULL, AEM_API_NOCONTENT);
}

static void private_update(void) {
	if (lenDecrypted != AEM_LEN_PRIVATE) return;

	const int sock = accountSocket(AEM_API_PRIVATE_UPDATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return;
	}

	close(sock);
	shortResponse(NULL, AEM_API_NOCONTENT);
}

static void setting_limits(void) {
	if (lenDecrypted != 12) return;

	const int sock = accountSocket(AEM_API_SETTING_LIMITS, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	unsigned char resp;
	if (recv(sock, &resp, 1, 0) != 1) {
		close(sock);
		return;
	} else if (resp == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(AEM_VIOLATION_SETTING_LIMITS);
		close(sock);
		return;
	} else if (resp != AEM_ACCOUNT_RESPONSE_OK) {
		close(sock);
		return;
	}

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Account");
		close(sock);
		return;
	}

	close(sock);
	shortResponse(NULL, AEM_API_NOCONTENT);
}

int aem_api_prepare(const unsigned char * const sealEnc, const bool ka) {
	if (sealEnc == NULL) return -1;
	keepAlive = ka;

	unsigned char sealDec[AEM_API_SEALBOX_SIZE - crypto_box_SEALBYTES];
	if (crypto_box_seal_open(sealDec, sealEnc, AEM_API_SEALBOX_SIZE, spk, ssk) != 0) return -1;

	postCmd = sealDec[0];
	memcpy(postNonce, sealDec + 1, crypto_box_NONCEBYTES);
	memcpy(upk, sealDec + 1 + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);

	const int sock = accountSocket(AEM_API_INTERNAL_EXIST, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return -1;

	unsigned char resp;
	recv(sock, &resp, 1, 0);
	close(sock);
	return (resp == '\x01') ? 0 : -1;
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
	lenResponse = -1;

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
		case AEM_API_MESSAGE_UPLOAD: message_upload(); break;

		case AEM_API_PRIVATE_UPDATE: private_update(); break;
		case AEM_API_SETTING_LIMITS: setting_limits(); break;
	}

	clearDecrypted();
	sodium_memzero(upk, crypto_box_PUBLICKEYBYTES);

	if (lenResponse < 0) shortResponse(NULL, AEM_API_ERROR);
	if (lenResponse < 0) return -1;

	*response_p = response;
	return lenResponse;
}
