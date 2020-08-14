#include <ctype.h> // for islower
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/ssl.h>
#include <sodium.h>

#include "../Global.h"
#include "../Common/Addr32.h"

#include "SendMail.h"

#include "post.h"

#define AEM_VIOLATION_ACCOUNT_CREATE 0x72436341
#define AEM_VIOLATION_ACCOUNT_DELETE 0x65446341
#define AEM_VIOLATION_ACCOUNT_UPDATE 0x70556341
#define AEM_VIOLATION_SETTING_LIMITS 0x694c6553

#define AEM_LEN_URL_POST 14 // 'account/browse'
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
static unsigned char accessKey_account[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_enquiry[AEM_LEN_ACCESSKEY];
static unsigned char sign_skey[crypto_sign_SECRETKEYBYTES];
static pid_t pid_account = 0;
static pid_t pid_storage = 0;
static pid_t pid_enquiry = 0;

void setApiKey(const unsigned char * const seed) {
	crypto_box_seed_keypair(spk, ssk, seed);
}

void setSigKey(const unsigned char * const src) {
	unsigned char seed[crypto_sign_SEEDBYTES];
	crypto_kdf_derive_from_key(seed, crypto_sign_SEEDBYTES, 1, "AEM-Sign", src);

	unsigned char tmp[crypto_sign_PUBLICKEYBYTES];
	crypto_sign_seed_keypair(tmp, sign_skey, seed);

	setMsgIdKeys(src);
}

void setAccessKey_account(const unsigned char * const newKey) {memcpy(accessKey_account, newKey, AEM_LEN_ACCESSKEY);}
void setAccessKey_storage(const unsigned char * const newKey) {memcpy(accessKey_storage, newKey, AEM_LEN_ACCESSKEY);}
void setAccessKey_enquiry(const unsigned char * const newKey) {memcpy(accessKey_enquiry, newKey, AEM_LEN_ACCESSKEY);}

void setAccountPid(const pid_t pid) {pid_account = pid;}
void setStoragePid(const pid_t pid) {pid_storage = pid;}
void setEnquiryPid(const pid_t pid) {pid_enquiry = pid;}

int aem_api_init(void) {
	if (pid_account == 0 || pid_storage == 0 || pid_enquiry == 0) return -1;

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
}

static void clearDecrypted() {
	sodium_mprotect_readwrite(decrypted);
	sodium_memzero(decrypted, AEM_API_BOX_SIZE_MAX);
	sodium_mprotect_noaccess(decrypted);
}

#include "../Common/Message.c"
#include "../Common/UnixSocketClient.c"

static void userViolation(const int violation) {
	syslog(LOG_WARNING, "Violation");
	// ...
}

static void shortResponse(const unsigned char * const data, const int len) {
	if (len != AEM_API_ERROR && (len < 0 || len > 32)) return;

	memcpy(response, keepAlive?
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Content-Length: 73\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store, no-transform\r\n"
		"Connection: Keep-Alive\r\n"
		"Keep-Alive: timeout=30\r\n"
		"\r\n"
	:
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Content-Length: 73\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store, no-transform\r\n"
		"Connection: close\r\n"
		"Padding-Ignore: abcdefghijk\r\n"
		"\r\n"
	, 277);

	randombytes_buf(response + 277, crypto_box_NONCEBYTES);

	unsigned char clr[33];
	if (len == AEM_API_ERROR) {
		memset(clr, 0xFF, 33);
	} else {
		bzero(clr, 33);
		clr[0] = len;
		if (data != NULL && len > 0) memcpy(clr + 1, data, len);
	}

	const int ret = crypto_box_easy(response + 277 + crypto_box_NONCEBYTES, clr, 33, response + 277, upk, ssk);
	if (ret == 0) lenResponse = 350;
}

static void account_browse(void) {
	if (lenDecrypted != 1) return;

	const int sock = accountSocket(AEM_API_ACCOUNT_BROWSE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	unsigned char *clr = malloc(1048576);
	if (clr == NULL) {syslog(LOG_ERR, "Failed malloc()"); return;}

	const ssize_t lenClr = recv(sock, clr, 1048576, MSG_WAITALL);
	close(sock);

	if (lenClr < 10) {free(clr); return;}

	sprintf((char*)response,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Content-Length: %zu\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store, no-transform\r\n"
		"%s"
		"\r\n",
	lenClr + crypto_box_NONCEBYTES + crypto_box_MACBYTES, keepAlive ?
		"Connection: Keep-Alive\r\n"
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
	if (recv(sock, &resp, 1, 0) != 1) {
		close(sock);
		return;
	} else if (resp == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(AEM_VIOLATION_ACCOUNT_CREATE);
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

static void account_delete(void) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) return;

	const int sock = accountSocket(AEM_API_ACCOUNT_DELETE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	unsigned char resp;
	if (recv(sock, &resp, 1, 0) != 1) {
		close(sock);
		return;
	} else if (resp == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(AEM_VIOLATION_ACCOUNT_DELETE);
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

static void account_update(void) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES + 1) return;

	const int sock = accountSocket(AEM_API_ACCOUNT_UPDATE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	unsigned char resp;
	if (recv(sock, &resp, 1, 0) != 1) {
		close(sock);
		return;
	} else if (resp == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(AEM_VIOLATION_ACCOUNT_UPDATE);
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
		if (ret == 1) shortResponse(NULL, AEM_API_NOCONTENT);
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

	close(sock);
	shortResponse(NULL, AEM_API_NOCONTENT);
}

static void address_lookup(void) {
	if (lenDecrypted > 99) return;

	if (memchr(decrypted, '@', lenDecrypted) != NULL) {
		// TODO: Email lookup
		unsigned char zeroes[32];
		bzero(zeroes, 32);
		shortResponse(zeroes, 32);
		return;
	}

	unsigned char addr[16];
	addr[0] = (lenDecrypted == 16) ? 'S' : 'N';
	addr32_store(addr + 1, (const char * const)decrypted, lenDecrypted);

	const int sock = accountSocket(AEM_API_ADDRESS_LOOKUP, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	unsigned char addr_pk[32];
	if (send(sock, addr, 16, 0) != 16) {close(sock); return;}
	if (recv(sock, addr_pk, 32, 0) != 32) {close(sock); return;}
	close(sock);

	shortResponse(addr_pk, 32);
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

	unsigned char *msg = malloc(5 + lenDecrypted);
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
	if (sock < 0) return;

	const ssize_t sentBytes = send(sock, enc, lenEnc, 0);
	close(sock);

	if (sentBytes != (ssize_t)lenEnc) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		return;
	}

	shortResponse(NULL, AEM_API_NOCONTENT);
}

static void message_browse(void) {
	unsigned char sockMsg[crypto_box_PUBLICKEYBYTES + 17];
	memcpy(sockMsg, upk, crypto_box_PUBLICKEYBYTES);

	if (lenDecrypted == 17)
		memcpy(sockMsg + crypto_box_PUBLICKEYBYTES, decrypted, lenDecrypted);
	else if (lenDecrypted != 1) return;

	// Data to boxed
	unsigned char * const clr = sodium_malloc(AEM_MAXLEN_MSGDATA + 9999);
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
	if (sock < 0) return;

	const ssize_t lenRcv = recv(sock, clr + lenClr, AEM_MAXLEN_MSGDATA, MSG_WAITALL);
	close(sock);
	if (lenRcv < 1) {sodium_free(clr); return;}
	lenClr += lenRcv;

	const char * const kaStr = keepAlive ? "Connection: Keep-Alive\r\nKeep-Alive: timeout=30\r\n" : "";

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

	unsigned char pk[32];
	if (send(sock, addrData, 11, 0) != 11) {close(sock); return false;}
	if (recv(sock, pk, crypto_box_PUBLICKEYBYTES, 0) != crypto_box_PUBLICKEYBYTES) {close(sock); return false;}
	close(sock);

	return memcmp(ver_pk, pk, crypto_box_PUBLICKEYBYTES) == 0;
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

static void message_create_ext(void) {
	const int userLevel = getUserLevel(upk);
	if ((userLevel & 3) < AEM_MINLEVEL_SENDEMAIL) return;

	// Address From
	unsigned char *sep = memchr(decrypted + 1, '\n', lenDecrypted - 1);
	if (sep == NULL) return;
	const unsigned char * const addrFrom = decrypted + 1;
	const size_t lenAddrFrom = sep - addrFrom;
	if (lenAddrFrom < 1) return;
	unsigned char addrFrom32[10];
	bool fromShield = false;
	if (getAddr32(addrFrom32, (char*)addrFrom, lenAddrFrom, &fromShield) != 0) return;
	if (!addr32OwnedByPubkey(upk, addrFrom32, fromShield)) return;

	// Address To
	const unsigned char * const addrTo = sep + 1;
	sep = memchr(addrTo, '\n', (decrypted + lenDecrypted) - addrTo);
	if (sep == NULL) return;
	const size_t lenAddrTo = sep - addrTo;
	if (lenAddrTo < 6) return; //a@b.cd

	// ReplyID
	const unsigned char *replyId = sep + 1;
	sep = memchr(replyId, '\n', (decrypted + lenDecrypted) - replyId);
	if (sep == NULL) return;
	size_t lenReplyId = sep - replyId;
	if (lenReplyId < 6) {
		lenReplyId = 0;
		replyId = NULL;
	}

	// Title
	const unsigned char * const title = sep + 1;
	sep = memchr(title, '\n', (decrypted + lenDecrypted) - title);
	if (sep == NULL) return;
	const size_t lenTitle = sep - title;
	if (lenTitle < 3) return;

	// Body
	const unsigned char * const body = sep + 1;
	const size_t lenBody = (decrypted + lenDecrypted) - body;
	if (lenBody < 1) return;

	// ToDomain
	const unsigned char *toDomain = memchr(addrTo + 1, '@', lenAddrTo - 1);
	if (toDomain == NULL) return;
	toDomain++;
	const size_t lenToDomain = (addrTo + lenAddrTo) - toDomain;
	if (lenToDomain < 4) return; // a.bc

	const int sock = enquirySocket(AEM_DNS_LOOKUP, toDomain, lenToDomain);
	if (sock < 0) return;

	uint32_t ip = 0;
	recv(sock, &ip, 4, 0);
	close(sock);
	if (ip == 0) {
		syslog(LOG_ERR, "DNS lookup failed");
		return;
	}

	const unsigned char ret = sendMail(ip, upk, userLevel,
		replyId,  lenReplyId,
		addrFrom, lenAddrFrom,
		addrTo,   lenAddrTo,
		title,    lenTitle,
		body,     lenBody
	);

	if (ret == 0) {
		shortResponse(NULL, AEM_API_NOCONTENT);
	} else {
		unsigned char x[32]; // Errcode + max 31 bytes
		x[0] = ret;
		shortResponse(x, 1);
	}
}

static void message_create_int(void) {
	const unsigned char * const fromAddr32 = decrypted;
	const unsigned char * const toAddr32   = decrypted + 10;
	const unsigned char * const toPubkey   = decrypted + 20;
	const unsigned char * const nonce      = decrypted + 20 + crypto_box_PUBLICKEYBYTES;
	const unsigned char * const body       = decrypted + 20 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES;
	const size_t lenBody = lenDecrypted - 20 - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES;

	if (!addr32OwnedByPubkey(upk,    fromAddr32, false)) return;
	if (!addr32OwnedByPubkey(toPubkey, toAddr32, false)) return;

	const int lenContent = AEM_INTMSG_HEADERS_LEN + lenBody;
	unsigned char content[lenContent];

	const uint16_t padAmount16 = (msg_getPadAmount(lenContent) << 6) | 16; // IntMsg: 32=0/16=1; 8/4/2/1=unused
	const uint32_t ts = (uint32_t)time(NULL);
	const unsigned char infoByte = getUserLevel(upk) & 3;

	memcpy(content + 0, &padAmount16, 2);
	memcpy(content + 2, &ts, 4);
	memcpy(content + 6, &infoByte,  1);
	memcpy(content + 7, upk, 32); // Sender's public key
	memcpy(content + 7 + crypto_box_PUBLICKEYBYTES, fromAddr32, 10);
	memcpy(content + 17 + crypto_box_PUBLICKEYBYTES, toAddr32, 10);
	memcpy(content + 27 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
	memcpy(content + AEM_INTMSG_HEADERS_LEN, body, lenBody);

	size_t lenEncrypted;
	unsigned char * const encrypted = msg_encrypt(toPubkey, content, lenContent, &lenEncrypted);
	sodium_memzero(content, lenContent);
	if (encrypted == NULL) {
		syslog(LOG_ERR, "Failed creating encrypted message");
		return;
	}

	// Store
	const int sock = storageSocket(lenEncrypted / 1024, toPubkey, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) {
		free(encrypted);
		return;
	}

	const ssize_t sentBytes = send(sock, encrypted, lenEncrypted, 0);
	free(encrypted);
	close(sock);

	if (sentBytes != (ssize_t)(lenEncrypted)) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		return;
	}

	shortResponse(NULL, AEM_API_NOCONTENT);
}

static void message_create(void) {
	// 'x' is 01111000 in ASCII. Addr32 understands this as a length of 16, which is higher than the maximum 15.
	return (decrypted[0] == 'x') ? message_create_ext() : message_create_int();
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
