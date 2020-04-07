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
#include "Include/https_common.h"

#include "post.h"

#define AEM_VIOLATION_ACCOUNT_CREATE 0x72436341
#define AEM_VIOLATION_ACCOUNT_DELETE 0x65446341
#define AEM_VIOLATION_ACCOUNT_UPDATE 0x70556341
#define AEM_VIOLATION_SETTING_LIMITS 0x694c6553

#define AEM_API_ERROR -1
#define AEM_API_NOCONTENT 0
#define AEM_MAXLEN_RESPONSE 132096

static bool keepAlive;
static unsigned char upk[crypto_box_PUBLICKEYBYTES];
static unsigned char response[AEM_MAXLEN_RESPONSE];
static int lenResponse = AEM_API_ERROR;
static unsigned char *decrypted;
#define lenDecrypted *((const uint16_t * const)(decrypted + AEM_HTTPS_POST_SIZE))

static unsigned char ssk[crypto_box_SECRETKEYBYTES];
static unsigned char accessKey_account[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage[AEM_LEN_ACCESSKEY];

void setApiKey(const unsigned char * const newKey) {
	memcpy(ssk, newKey, crypto_box_PUBLICKEYBYTES);
}

void setAccessKey_account(const unsigned char * const newKey) {memcpy(accessKey_account, newKey, AEM_LEN_ACCESSKEY);}
void setAccessKey_storage(const unsigned char * const newKey) {memcpy(accessKey_storage, newKey, AEM_LEN_ACCESSKEY);}

int aem_api_init(void) {
	decrypted = sodium_malloc(AEM_HTTPS_POST_SIZE + 2);
	return (decrypted != NULL) ? 0 : -1;
}

void aem_api_free(void) {
	sodium_free(decrypted);
}

static void clearDecrypted() {
	sodium_mprotect_readwrite(decrypted);
	sodium_memzero(decrypted, AEM_HTTPS_POST_SIZE + 2);
	sodium_mprotect_noaccess(decrypted);
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

static int accountSocket(const unsigned char command, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket to Account: %m"); return -1;}

	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, "Account.sck");

	if (connect(sock, (struct sockaddr*)&sa, strlen(sa.sun_path) + sizeof(sa.sun_family)) == -1) {
		syslog(LOG_ERR, "Failed connecting to Account");
		close(sock);
		return -1;
	}

	const size_t lenClear = crypto_box_PUBLICKEYBYTES + 1;
	unsigned char clear[lenClear];
	clear[0] = command;
	memcpy(clear + 1, pubkey, crypto_box_PUBLICKEYBYTES);

	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear;
	unsigned char encrypted[lenEncrypted];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear, encrypted, accessKey_account);

	if (send(sock, encrypted, lenEncrypted, 0) != lenEncrypted) {
		syslog(LOG_ERR, "Failed sending data to Account");
		close(sock);
		return -1;
	}

	return sock;
}

static int storageSocket(const unsigned char command) {
	const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket to Storage: %m"); return -1;}

	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, "Storage.sck");

	if (connect(sock, (struct sockaddr*)&sa, strlen(sa.sun_path) + sizeof(sa.sun_family)) == -1) {
		syslog(LOG_ERR, "Failed connecting to Storage");
		close(sock);
		return -1;
	}

	const size_t lenClear = 1 + crypto_box_PUBLICKEYBYTES;
	unsigned char clear[lenClear];
	clear[0] = command;
	memcpy(clear + 1, upk, crypto_box_PUBLICKEYBYTES);

	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear;
	unsigned char encrypted[lenEncrypted];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear, encrypted, accessKey_storage);

	if (send(sock, encrypted, lenEncrypted, 0) != lenEncrypted) {
		syslog(LOG_ERR, "Failed sending data to Storage");
		close(sock);
		return -1;
	}

	return sock;
}

static void userViolation(const int violation) {
	syslog(LOG_WARNING, "Violation");
	// ...
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
		"Cache-Control: no-store, no-transform\r\n"
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
		"Padding-Ignore: abcdefghijk\r\n"
		"\r\n"
	, 281);

	const int sock = accountSocket(AEM_API_ACCOUNT_BROWSE, upk);
	if (sock < 0) return;

	unsigned char clr[131200];
	recv(sock, clr, 131200, MSG_WAITALL);
	close(sock);

	randombytes_buf(response + 281, crypto_box_NONCEBYTES);

	if (crypto_box_easy(response + 281 + crypto_box_NONCEBYTES, clr, 131200, response + 281, upk, ssk) == 0)
		lenResponse = 281 + 131240;
}

static void account_create(void) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) return;

	const int sock = accountSocket(AEM_API_ACCOUNT_CREATE, upk);
	if (sock < 0) return;

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		close(sock);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(AEM_VIOLATION_ACCOUNT_CREATE);
		close(sock);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
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

	const int sock = accountSocket(AEM_API_ACCOUNT_DELETE, upk);
	if (sock < 0) return;

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		close(sock);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(AEM_VIOLATION_ACCOUNT_DELETE);
		close(sock);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
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

	const int sock = accountSocket(AEM_API_ACCOUNT_UPDATE, upk);
	if (sock < 0) return;

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		close(sock);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(AEM_VIOLATION_ACCOUNT_UPDATE);
		close(sock);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
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
	if (lenDecrypted != 13 && (lenDecrypted != 6 || memcmp(decrypted, "SHIELD", 6) != 0)) return;

	const int sock = accountSocket(AEM_API_ADDRESS_CREATE, upk);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_ERR, "Failed sending data to Account");
		close(sock);
		return;
	}

	if (lenDecrypted == 13) { // Normal
		unsigned char ret;
		recv(sock, &ret, 1, 0);
		close(sock);
		if (ret == 1) shortResponse(NULL, AEM_API_NOCONTENT);
		return;
	}

	// Shield
	unsigned char data[28];
	if (
	   recv(sock, data, 13, 0) != 13
	|| recv(sock, data + 13, 15, 0) != 15
	) {syslog(LOG_ERR, "Failed receiving data from Account"); close(sock); return;}

	close(sock);
	shortResponse(data, 28);
}

static void address_delete(void) {
	if (lenDecrypted != 13) return;

	const int sock = accountSocket(AEM_API_ADDRESS_DELETE, upk);
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
		return;
	}

	unsigned char addr[16];
	addr[0] = (lenDecrypted == 24) ? 'S' : 'N';
	addr32_store(addr + 1, (const char * const)decrypted, lenDecrypted);

	const int sock = accountSocket(AEM_API_ADDRESS_LOOKUP, upk);
	if (sock < 0) return;

	unsigned char addr_pk[32];
	if (send(sock, addr, 16, 0) != 16) {close(sock); return;}
	if (recv(sock, addr_pk, 32, 0) != 32) {close(sock); return;}
	close(sock);

	shortResponse(addr_pk, 32);
}

static void address_update(void) {
	if (lenDecrypted % 14 != 0) return;

	const int sock = accountSocket(AEM_API_ADDRESS_UPDATE, upk);
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

	const int sock = storageSocket(lenDecrypted / 1024);
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
	if (lenDecrypted != 1) return;

	memcpy(response, keepAlive?
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Content-Length: 131240\r\n"
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
		"Content-Length: 131240\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Cache-Control: no-store, no-transform\r\n"
		"Connection: close\r\n"
		"Padding-Ignore: abcdefghijk\r\n"
		"\r\n"
	, 281);

	const int sock = storageSocket(UINT8_MAX);
	if (sock < 0) return;

	unsigned char clr[131200];
	recv(sock, clr, 131200, MSG_WAITALL);
	close(sock);

	randombytes_buf(response + 281, crypto_box_NONCEBYTES);

	if (crypto_box_easy(response + 281 + crypto_box_NONCEBYTES, clr, 131200, response + 281, upk, ssk) == 0)
		lenResponse = 281 + 131240;
}

static bool addr32OwnedByPubkey(const unsigned char * const ver_pk, const unsigned char * const ver_addr32, const bool shield) {
	unsigned char addrData[16];
	addrData[0] = shield? 'S' : 'N';
	memcpy(addrData + 1, ver_addr32, 15);

	const int sock = accountSocket(AEM_API_ADDRESS_LOOKUP, ver_pk);
	if (sock < 0) return false;

	unsigned char pk[32];
	if (send(sock, addrData, 16, 0) != 16) {close(sock); return false;}
	if (recv(sock, pk, crypto_box_PUBLICKEYBYTES, 0) != crypto_box_PUBLICKEYBYTES) {close(sock); return false;}
	close(sock);

	return memcmp(ver_pk, pk, crypto_box_PUBLICKEYBYTES) == 0;
}

static unsigned char getUserLevel(const unsigned char * const pubkey) {
	const int sock = accountSocket(AEM_API_INTERNAL_LEVEL, pubkey);
	if (sock < 0) return 0;

	unsigned char ret;
	recv(sock, &ret, 1, 0);
	close(sock);
	return ret;
}

static void message_create(void) {
	unsigned char * const fromAddr32 = decrypted;
	unsigned char * const toAddr32   = decrypted + 15;
	unsigned char * const toPubkey   = decrypted + 30;
	unsigned char * const bodyBox    = decrypted + 30 + crypto_box_PUBLICKEYBYTES;
	const size_t lenBodyBox = lenDecrypted - 30 - crypto_box_PUBLICKEYBYTES;

	if (!addr32OwnedByPubkey(upk, fromAddr32, false)) return;
	if (!addr32OwnedByPubkey(toPubkey, toAddr32, false)) return;

	if ((lenBodyBox + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES) % 1024 != 0) return;

	const size_t kib = (lenBodyBox + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES) / 1024;

	const uint32_t ts = (uint32_t)time(NULL);
	unsigned char infoByte = getUserLevel(upk) & 3;

	unsigned char headbox_clear[AEM_HEADBOX_SIZE];
	headbox_clear[0] = infoByte;
	memcpy(headbox_clear +  1, &ts, 4);
	memcpy(headbox_clear +  5, fromAddr32, 15);
	memcpy(headbox_clear + 20, toAddr32,   15);

	unsigned char headBox[AEM_HEADBOX_SIZE + crypto_box_SEALBYTES];
	crypto_box_seal(headBox, headbox_clear, AEM_HEADBOX_SIZE, toPubkey);
	sodium_memzero(headbox_clear, AEM_HEADBOX_SIZE);

	const size_t bsLen = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + lenBodyBox;
	unsigned char * const boxSet = malloc(bsLen);
	if (boxSet == NULL) return;

	memcpy(boxSet, headBox, AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	memcpy(boxSet + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES, bodyBox, lenBodyBox);

	// Store
	const int sock = storageSocket(kib);
	if (sock < 0) {
		free(boxSet);
		return;
	}

	const ssize_t sentBytes = send(sock, boxSet, kib * 1024, 0);
	free(boxSet);
	close(sock);

	if (sentBytes != (ssize_t)(kib * 1024)) {
		syslog(LOG_ERR, "Failed communicating with Storage");
		return;
	}

	shortResponse(NULL, AEM_API_NOCONTENT);
}

static void message_delete(void) {
	if (lenDecrypted % 16 != 0) return;

	const int sock = storageSocket(0);
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

	const int sock = accountSocket(AEM_API_PRIVATE_UPDATE, upk);
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

	const int sock = accountSocket(AEM_API_SETTING_LIMITS, upk);
	if (sock < 0) return;

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		close(sock);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(AEM_VIOLATION_SETTING_LIMITS);
		close(sock);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
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

int aem_api_prepare(const unsigned char * const pubkey, const bool ka) {
	const int sock = accountSocket(AEM_API_INTERNAL_EXIST, pubkey);
	if (sock < 0) return -1;

	unsigned char response;
	recv(sock, &response, 1, 0);
	close(sock);
	if (response != 1) return -1;

	memcpy(upk, pubkey, crypto_box_PUBLICKEYBYTES);
	keepAlive = ka;
	return 0;
}

__attribute__((warn_unused_result))
int aem_api_process(mbedtls_ssl_context * const ssl, const char * const url, const unsigned char * const post) {
	if (ssl == NULL || url == NULL || post == NULL) return -1;

	sodium_mprotect_readwrite(decrypted);
	if (crypto_box_open_easy(decrypted, post + crypto_box_NONCEBYTES, AEM_HTTPS_POST_SIZE + 2 + crypto_box_MACBYTES, post, upk, ssk) != 0) {
		sodium_mprotect_noaccess(decrypted);
		return -1;
	}
	if (lenDecrypted < 1) return -1;

	sodium_mprotect_readonly(decrypted);
	lenResponse = -1;

	     if (memcmp(url, "account/browse", 14) == 0) account_browse();
	else if (memcmp(url, "account/create", 14) == 0) account_create();
	else if (memcmp(url, "account/delete", 14) == 0) account_delete();
	else if (memcmp(url, "account/update", 14) == 0) account_update();

	else if (memcmp(url, "address/create", 14) == 0) address_create();
	else if (memcmp(url, "address/delete", 14) == 0) address_delete();
	else if (memcmp(url, "address/lookup", 14) == 0) address_lookup();
	else if (memcmp(url, "address/update", 14) == 0) address_update();

	else if (memcmp(url, "message/assign", 14) == 0) message_assign();
	else if (memcmp(url, "message/browse", 14) == 0) message_browse();
	else if (memcmp(url, "message/create", 14) == 0) message_create();
	else if (memcmp(url, "message/delete", 14) == 0) message_delete();

	else if (memcmp(url, "private/update", 14) == 0) private_update();
	else if (memcmp(url, "setting/limits", 14) == 0) setting_limits();

	if (lenResponse < 0) shortResponse(NULL, AEM_API_ERROR);
	if (lenResponse > 0) sendData(ssl, response, lenResponse);

	bzero(response, AEM_MAXLEN_RESPONSE);
	clearDecrypted();
	sodium_memzero(upk, crypto_box_PUBLICKEYBYTES);
	return 0;
}
