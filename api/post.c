#define _GNU_SOURCE // for peercred

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

#include "Include/Addr32.h"
#include "Include/tls_common.h"

#include "SendMail.h"

#include "post.h"

#define AEM_VIOLATION_ACCOUNT_CREATE 0x72436341
#define AEM_VIOLATION_ACCOUNT_DELETE 0x65446341
#define AEM_VIOLATION_ACCOUNT_UPDATE 0x70556341
#define AEM_VIOLATION_SETTING_LIMITS 0x694c6553

#define AEM_LEN_URL_POST 14 // 'account/browse'
#define AEM_API_ERROR -1
#define AEM_API_NOCONTENT 0
#define AEM_MAXLEN_RESPONSE 132096

static bool keepAlive;
static char postUrl[AEM_LEN_URL_POST];
static unsigned char postNonce[crypto_box_NONCEBYTES];

static unsigned char upk[crypto_box_PUBLICKEYBYTES];
static unsigned char response[AEM_MAXLEN_RESPONSE];
static int lenResponse = AEM_API_ERROR;
static unsigned char *decrypted;
static uint16_t lenDecrypted;

static unsigned char spk[crypto_box_PUBLICKEYBYTES];
static unsigned char ssk[crypto_box_SECRETKEYBYTES];
static unsigned char accessKey_account[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_enquiry[AEM_LEN_ACCESSKEY];
static unsigned char sign_skey[crypto_sign_SECRETKEYBYTES];
static pid_t pid_account = 0;
static pid_t pid_storage = 0;
static pid_t pid_enquiry = 0;

void setApiKey(const unsigned char * const newKey) {
	memcpy(ssk, newKey, crypto_box_PUBLICKEYBYTES);
	crypto_scalarmult_base(spk, ssk);
}

void setSignKey(const unsigned char * const seed) {
	unsigned char tmp[crypto_sign_PUBLICKEYBYTES];
	crypto_sign_seed_keypair(tmp, sign_skey, seed);
}

void setAccessKey_account(const unsigned char * const newKey) {memcpy(accessKey_account, newKey, AEM_LEN_ACCESSKEY);}
void setAccessKey_storage(const unsigned char * const newKey) {memcpy(accessKey_storage, newKey, AEM_LEN_ACCESSKEY);}
void setAccessKey_enquiry(const unsigned char * const newKey) {memcpy(accessKey_enquiry, newKey, AEM_LEN_ACCESSKEY);}

void setAccountPid(const pid_t pid) {pid_account = pid;}
void setStoragePid(const pid_t pid) {pid_storage = pid;}
void setEnquiryPid(const pid_t pid) {pid_enquiry = pid;}

int aem_api_init(void) {
	if (pid_account == 0 || pid_storage == 0 || pid_enquiry == 0) return -1;

	decrypted = sodium_malloc(AEM_API_POST_SIZE);
	return (decrypted != NULL) ? 0 : -1;
}

void aem_api_free(void) {
	sodium_free(decrypted);
}

static void clearDecrypted() {
	sodium_mprotect_readwrite(decrypted);
	sodium_memzero(decrypted, AEM_API_POST_SIZE);
	sodium_mprotect_noaccess(decrypted);
}

#include "../Common/UnixSocketClient.c"

static void userViolation(const int violation) {
	syslog(LOG_WARNING, "Violation");
	// ...
}

static void shortResponse(const unsigned char * const data, const int len) {
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

	memcpy(response, keepAlive?
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Content-Length: 131240\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store,      no-transform\r\n"
		"Connection: Keep-Alive\r\n"
		"Keep-Alive: timeout=30\r\n"
		"\r\n"
	:
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Content-Length: 131240\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store, no-transform\r\n"
		"Connection: close\r\n"
		"Padding-Ignore: abcdefghijklmnop\r\n"
		"\r\n"
	, 286);

	const int sock = accountSocket(AEM_API_ACCOUNT_BROWSE, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	unsigned char clr[131200];
	const ssize_t rbytes = recv(sock, clr, 131200, MSG_WAITALL);
	close(sock);

	if (rbytes != 131200) {
		syslog(LOG_WARNING, "Failed receiving data from Account");
		return;
	}

	randombytes_buf(response + 286, crypto_box_NONCEBYTES);
	if (crypto_box_easy(response + 286 + crypto_box_NONCEBYTES, clr, 131200, response + 286, upk, ssk) == 0)
		lenResponse = 286 + crypto_box_NONCEBYTES + crypto_box_MACBYTES + 131200;
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

static void message_assign(void) {
	if (lenDecrypted % 1024 != 0) return;

	const int sock = storageSocket(lenDecrypted / 1024, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	const ssize_t sentBytes = send(sock, decrypted, lenDecrypted, 0);
	close(sock);

	if (sentBytes != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		return;
	}

	shortResponse(NULL, AEM_API_NOCONTENT);
}

static void message_browse(void) {
	if (lenDecrypted != 16) return;

	memcpy(response, keepAlive?
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Content-Length: 131245\r\n"
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
		"Content-Length: 131245\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store, no-transform\r\n"
		"Connection: close\r\n"
		"Padding-Ignore: abcdefghijk\r\n"
		"\r\n"
	, 281);

	const int sock = storageSocket(UINT8_MAX, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != lenDecrypted) {close(sock); return;}

	unsigned char clr[131205];
	const ssize_t rbytes = recv(sock, clr, 131205, MSG_WAITALL);
	close(sock);

	if (rbytes != 131205) {
		syslog(LOG_WARNING, "Failed receiving data from Storage");
		return;
	}

	randombytes_buf(response + 281, crypto_box_NONCEBYTES);
	if (crypto_box_easy(response + 281 + crypto_box_NONCEBYTES, clr, 131205, response + 281, upk, ssk) == 0)
		lenResponse = 281 + crypto_box_NONCEBYTES + crypto_box_MACBYTES + 131205;
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

#include "../Common/Message.c"

static void message_create_ext(void) {
	// Address From
	unsigned char *sep = memchr(decrypted + 1, '\n', lenDecrypted - 1);
	if (sep == NULL) return;
	const unsigned char * const addrFrom = decrypted + 1;
	const size_t lenAddrFrom = sep - addrFrom;
	if (lenAddrFrom < 1) return;
	// TODO: Verify ownership of address

	// Address To
	const unsigned char * const addrTo = sep + 1;
	sep = memchr(addrTo, '\n', (decrypted + lenDecrypted) - addrTo);
	if (sep == NULL) return;
	const size_t lenAddrTo = sep - addrTo;
	if (lenAddrTo < 6) return; //a@b.cd

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

	sendMail(ip, addrFrom, lenAddrFrom, addrTo, lenAddrTo, title, lenTitle, body, lenBody);
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

	const int sock = storageSocket(0, upk, crypto_box_PUBLICKEYBYTES);
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

	memcpy(&lenDecrypted, sealDec, 2);
	memcpy(postUrl, sealDec + 2, 14);
	memcpy(postNonce, sealDec + 16, crypto_box_NONCEBYTES);
	memcpy(upk, sealDec + 16 + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);

	const int sock = accountSocket(AEM_API_INTERNAL_EXIST, upk, crypto_box_PUBLICKEYBYTES);
	if (sock < 0) return -1;

	unsigned char resp;
	recv(sock, &resp, 1, 0);
	close(sock);
	return (resp == '\x01') ? 0 : -1;
}

__attribute__((warn_unused_result))
int aem_api_process(mbedtls_ssl_context * const ssl, const unsigned char * const postBox) {
	if (ssl == NULL || postBox == NULL) return -1;

	sodium_mprotect_readwrite(decrypted);
	if (crypto_box_open_easy(decrypted, postBox, AEM_API_POST_SIZE + crypto_box_MACBYTES, postNonce, upk, ssk) != 0) {
		sodium_mprotect_noaccess(decrypted);
		return -1;
	}
	if (lenDecrypted < 1) return -1;

	sodium_mprotect_readonly(decrypted);
	lenResponse = -1;

	     if (memcmp(postUrl, "account/browse", 14) == 0) account_browse();
	else if (memcmp(postUrl, "account/create", 14) == 0) account_create();
	else if (memcmp(postUrl, "account/delete", 14) == 0) account_delete();
	else if (memcmp(postUrl, "account/update", 14) == 0) account_update();

	else if (memcmp(postUrl, "address/create", 14) == 0) address_create();
	else if (memcmp(postUrl, "address/delete", 14) == 0) address_delete();
	else if (memcmp(postUrl, "address/lookup", 14) == 0) address_lookup();
	else if (memcmp(postUrl, "address/update", 14) == 0) address_update();

	else if (memcmp(postUrl, "message/assign", 14) == 0) message_assign();
	else if (memcmp(postUrl, "message/browse", 14) == 0) message_browse();
	else if (memcmp(postUrl, "message/create", 14) == 0) message_create();
	else if (memcmp(postUrl, "message/delete", 14) == 0) message_delete();

	else if (memcmp(postUrl, "private/update", 14) == 0) private_update();
	else if (memcmp(postUrl, "setting/limits", 14) == 0) setting_limits();

	if (lenResponse < 0) shortResponse(NULL, AEM_API_ERROR);
	if (lenResponse > 0) sendData(ssl, response, lenResponse);

	bzero(response, AEM_MAXLEN_RESPONSE);
	clearDecrypted();
	sodium_memzero(upk, crypto_box_PUBLICKEYBYTES);
	return 0;
}
