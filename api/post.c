#include <ctype.h> // for islower
#include <stdbool.h>
#include <errno.h>
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

static unsigned char ssk[crypto_box_SECRETKEYBYTES];
static unsigned char accessKey_account[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage[AEM_LEN_ACCESSKEY];

void setApiKey(const unsigned char * const newKey) {
	memcpy(ssk, newKey, crypto_box_PUBLICKEYBYTES);
}

void setAccessKey_account(const unsigned char * const newKey) {memcpy(accessKey_account, newKey, AEM_LEN_ACCESSKEY);}
void setAccessKey_storage(const unsigned char * const newKey) {memcpy(accessKey_storage, newKey, AEM_LEN_ACCESSKEY);}

static bool keepAlive;
void setKeepAlive(const bool ka) {keepAlive = ka;}

void https_pubkey(mbedtls_ssl_context * const ssl) {
	unsigned char data[256];

	memcpy(data, keepAlive?
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Content-Length: 32\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Pad: abcdefghijklmnopqrstuvwxyz0\r\n"
		"\r\n"
	:
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"Expect-CT: enforce, max-age=99999999\r\n"
		"Content-Length: 32\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Connection: close\r\n"
		"Pad: abcdefgh\r\n"
		"\r\n"
	, 224);

	crypto_scalarmult_base(data + 224, ssk);

	sendData(ssl, data, 256);
}

static void sendEncrypted(mbedtls_ssl_context * const ssl, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const unsigned char * const data, const size_t len) {
	if (len > 32) return;

	unsigned char final[350];

	memcpy(final, keepAlive?
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

	randombytes_buf(final + 277, crypto_box_NONCEBYTES);

	unsigned char clr[33];
	bzero(clr, 33);
	clr[0] = len;
	if (len > 0) memcpy(clr + 1, data, len);

	const int ret = crypto_box_easy(final + 277 + crypto_box_NONCEBYTES, clr, 33, final + 277, pubkey, ssk);

	if (ret == 0) sendData(ssl, final, 350);
}

static int accountSocket(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const unsigned char command) {
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, "Account.sck");

	const int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		syslog(LOG_MAIL | LOG_ERR, "Failed creating socket to Account");
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&sa, strlen(sa.sun_path) + sizeof(sa.sun_family)) == -1) {
		syslog(LOG_MAIL | LOG_ERR, "Failed connecting to Account");
		return -1;
	}

	const size_t lenClear = crypto_box_PUBLICKEYBYTES + 1;
	unsigned char clear[lenClear];
	clear[0] = command;
	memcpy(clear+ 1, pubkey, crypto_box_PUBLICKEYBYTES);

	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear;
	unsigned char encrypted[lenEncrypted];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear, encrypted, accessKey_account);

	if (send(sock, encrypted, lenEncrypted, 0) != lenEncrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed sending data to Account");
		close(sock);
		return -1;
	}

	return sock;
}

static int storageSocket(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const unsigned char command) {
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, "Storage.sck");

	const int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		syslog(LOG_MAIL | LOG_ERR, "Failed creating socket to Storage");
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&sa, strlen(sa.sun_path) + sizeof(sa.sun_family)) == -1) {
		syslog(LOG_MAIL | LOG_ERR, "Failed connecting to Storage");
		return -1;
	}

	const size_t lenClear = 1 + crypto_box_PUBLICKEYBYTES;
	unsigned char clear[lenClear];
	clear[0] = command;
	memcpy(clear + 1, pubkey, crypto_box_PUBLICKEYBYTES);

	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear;
	unsigned char encrypted[lenEncrypted];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear, encrypted, accessKey_storage);

	if (send(sock, encrypted, lenEncrypted, 0) != lenEncrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed sending data to Storage");
		close(sock);
		return -1;
	}

	return sock;
}

static void userViolation(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const int violation) {
	syslog(LOG_MAIL | LOG_WARNING, "Violation");
	// ...
}

static void account_browse(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	sodium_free(*decrypted);
	if (lenDecrypted != 1) return;

	unsigned char response[281 + 131240];

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

	const int sock = accountSocket(pubkey, AEM_API_ACCOUNT_BROWSE);
	if (sock < 0) return;

	unsigned char clr[131200];
	recv(sock, clr, 131200, MSG_WAITALL);
	close(sock);

	randombytes_buf(response + 281, crypto_box_NONCEBYTES);

	if (crypto_box_easy(response + 281 + crypto_box_NONCEBYTES, clr, 131200, response + 281, pubkey, ssk) == 0)
		sendData(ssl, response, 281 + 131240);
}

static void account_create(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_ACCOUNT_CREATE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		sodium_free(*decrypted);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(pubkey, AEM_VIOLATION_ACCOUNT_CREATE);
		sodium_free(*decrypted);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
		sodium_free(*decrypted);
		return;
	}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static void account_delete(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_ACCOUNT_DELETE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		sodium_free(*decrypted);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(pubkey, AEM_VIOLATION_ACCOUNT_DELETE);
		sodium_free(*decrypted);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
		sodium_free(*decrypted);
		return;
	}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static void account_update(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES + 1) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_ACCOUNT_UPDATE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		sodium_free(*decrypted);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(pubkey, AEM_VIOLATION_ACCOUNT_UPDATE);
		sodium_free(*decrypted);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
		sodium_free(*decrypted);
		return;
	}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static void address_create(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != 13 && (lenDecrypted != 6 || memcmp(*decrypted, "SHIELD", 6) != 0)) {
		sodium_free(*decrypted);
		return;
	}

	const int sock = accountSocket(pubkey, AEM_API_ADDRESS_CREATE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed sending data to Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);

	if (lenDecrypted == 13) { // Normal
		unsigned char ret;
		recv(sock, &ret, 1, 0);
		close(sock);

		if (ret == 1) sendEncrypted(ssl, pubkey, NULL, 0);
		return;
	}

	// Shield
	unsigned char data[28];
	if (
	   recv(sock, data, 13, 0) != 13
	|| recv(sock, data + 13, 15, 0) != 15
	) {syslog(LOG_MAIL | LOG_ERR, "Failed receiving data from Account"); close(sock); return;}

	close(sock);

	sendEncrypted(ssl, pubkey, data, 28);
}

static void address_delete(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != 13) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_ADDRESS_DELETE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static void address_lookup(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted > 99) {sodium_free(*decrypted); return;}

	if (memchr(*decrypted, '@', lenDecrypted) != NULL) {
		// TODO: Email lookup
		sodium_free(*decrypted);
		return;
	}

	unsigned char addr[16];
	addr[0] = (lenDecrypted == 24) ? 'S' : 'N';
	addr32_store(addr + 1, *decrypted, lenDecrypted);
	sodium_free(*decrypted);

	const int sock = accountSocket(pubkey, AEM_API_ADDRESS_LOOKUP);
	if (sock < 0) return;

	unsigned char addr_pk[32];
	if (send(sock, addr, 16, 0) != 16) {close(sock); return;}
	if (recv(sock, addr_pk, 32, 0) != 32) {close(sock); return;}
	close(sock);

	sendEncrypted(ssl, pubkey, addr_pk, 32);
}

static void address_update(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted % 14 != 0) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_ADDRESS_UPDATE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static void message_assign(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted % 1024 != 0) {sodium_free(*decrypted); return;}

	const int sock = storageSocket(pubkey, (lenDecrypted / 1024));
	if (sock < 0) {
		sodium_free(*decrypted);
		return;
	}

	const ssize_t sentBytes = send(sock, *decrypted, lenDecrypted, 0);

	sodium_free(*decrypted);
	close(sock);

	if (sentBytes != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Storage");
		return;
	}

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static void message_browse(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	sodium_free(*decrypted);
	if (lenDecrypted != 1) return;

	unsigned char response[281 + 131240];

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

	const int sock = storageSocket(pubkey, UINT8_MAX);
	if (sock < 0) return;

	unsigned char clr[131200];
	recv(sock, clr, 131200, MSG_WAITALL);
	close(sock);

	randombytes_buf(response + 281, crypto_box_NONCEBYTES);

	if (crypto_box_easy(response + 281 + crypto_box_NONCEBYTES, clr, 131200, response + 281, pubkey, ssk) == 0)
		sendData(ssl, response, 281 + 131240);
}

static bool addr32OwnedByPubkey(const unsigned char * const ver_pk, const unsigned char * const ver_addr32, const bool shield) {
	unsigned char addrData[16];
	addrData[0] = shield? 'S' : 'N';
	memcpy(addrData + 1, ver_addr32, 15);

	const int sock = accountSocket(ver_pk, AEM_API_ADDRESS_LOOKUP);
	if (sock < 0) return false;

	unsigned char pk[32];
	if (send(sock, addrData, 16, 0) != 16) {close(sock); return false;}
	if (recv(sock, pk, crypto_box_PUBLICKEYBYTES, 0) != crypto_box_PUBLICKEYBYTES) {close(sock); return false;}
	close(sock);

	return memcmp(ver_pk, pk, crypto_box_PUBLICKEYBYTES) == 0;
}

static unsigned char getUserLevel(const unsigned char * const pubkey) {
	const int sock = accountSocket(pubkey, AEM_API_INTERNAL_LEVEL);
	if (sock < 0) return false;

	unsigned char ret;
	recv(sock, &ret, 1, 0);
	return ret;
}

static void message_create(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	unsigned char * const fromAddr32 = (unsigned char*)*decrypted;
	unsigned char * const toAddr32   = (unsigned char*)*decrypted + 15;
	unsigned char * const toPubkey   = (unsigned char*)*decrypted + 30;
	unsigned char * const bodyBox    = (unsigned char*)*decrypted + 30 + crypto_box_PUBLICKEYBYTES;
	const size_t lenBodyBox = lenDecrypted - 30 - crypto_box_PUBLICKEYBYTES;

	if (!addr32OwnedByPubkey(pubkey, fromAddr32, false)) {sodium_free(*decrypted); return;}
	if (!addr32OwnedByPubkey(toPubkey, toAddr32, false)) {sodium_free(*decrypted); return;}

	if ((lenBodyBox + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES) % 1024 != 0) {sodium_free(*decrypted); return;}

	const size_t kib = (lenBodyBox + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES) / 1024;

	const uint32_t ts = (uint32_t)time(NULL);
	unsigned char infoByte = getUserLevel(pubkey) & 3;

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
	if (boxSet == NULL) {sodium_free(*decrypted); return;}

	memcpy(boxSet, headBox, AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	memcpy(boxSet + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES, bodyBox, lenBodyBox);

	// Store
	const int sock = storageSocket(toPubkey, kib);
	sodium_free(*decrypted);

	if (sock < 0) {
		free(boxSet);
		return;
	}

	const ssize_t sentBytes = send(sock, boxSet, kib * 1024, 0);
	free(boxSet);
	close(sock);

	if (sentBytes != (ssize_t)(kib * 1024)) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Storage");
		return;
	}

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static void message_delete(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted % 16 != 0) {sodium_free(*decrypted); return;}

	const int sock = storageSocket(pubkey, 0);
	if (sock < 0) {sodium_free(*decrypted); return;}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Storage");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static void private_update(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != AEM_LEN_PRIVATE) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_PRIVATE_UPDATE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static void setting_limits(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != 12) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_SETTING_LIMITS);
	if (sock < 0) {sodium_free(*decrypted); return;}

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		sodium_free(*decrypted);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
		userViolation(pubkey, AEM_VIOLATION_SETTING_LIMITS);
		sodium_free(*decrypted);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
		sodium_free(*decrypted);
		return;
	}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_ERR, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	sendEncrypted(ssl, pubkey, NULL, 0);
}

static bool pubkeyExists(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	const int sock = accountSocket(pubkey, AEM_API_INTERNAL_EXIST);
	if (sock < 0) return false;

	unsigned char response;
	recv(sock, &response, 1, 0);
	return (response == 1);
}

__attribute__((warn_unused_result))
static char *openWebBox(const unsigned char * const post, unsigned char * const pubkey, size_t * const lenDecrypted) {
	const size_t skipBytes = crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES;

	unsigned char nonce[crypto_box_NONCEBYTES];
	memcpy(nonce, post, crypto_box_NONCEBYTES);

	memcpy(pubkey, post + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);

	if (!pubkeyExists(pubkey)) return NULL;

	char * const decrypted = sodium_malloc(AEM_HTTPS_POST_SIZE + 2);
	if (decrypted == NULL) return NULL;

	const int ret = crypto_box_open_easy((unsigned char*)decrypted, post + skipBytes, AEM_HTTPS_POST_SIZE + 2 + crypto_box_MACBYTES, nonce, pubkey, ssk);
	if (ret != 0) {sodium_free(decrypted); return NULL;}
	sodium_mprotect_readonly(decrypted);

	uint16_t u16len;
	memcpy(&u16len, decrypted + AEM_HTTPS_POST_SIZE, 2);
	*lenDecrypted = u16len;

	return decrypted;
}

__attribute__((warn_unused_result))
int https_post(mbedtls_ssl_context * const ssl, const char * const url, const unsigned char * const post) {
	if (ssl == NULL || url == NULL || post == NULL) return -1;
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	size_t lenDecrypted;

	char * const decrypted = openWebBox(post, pubkey, &lenDecrypted);
	if (decrypted == NULL || lenDecrypted < 1) return -1;

	else if (memcmp(url, "account/browse", 14) == 0) account_browse(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "account/create", 14) == 0) account_create(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "account/delete", 14) == 0) account_delete(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "account/update", 14) == 0) account_update(ssl, &decrypted, lenDecrypted, pubkey);

	else if (memcmp(url, "address/create", 14) == 0) address_create(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "address/delete", 14) == 0) address_delete(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "address/lookup", 14) == 0) address_lookup(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "address/update", 14) == 0) address_update(ssl, &decrypted, lenDecrypted, pubkey);

	else if (memcmp(url, "message/assign", 14) == 0) message_assign(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "message/browse", 14) == 0) message_browse(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "message/create", 14) == 0) message_create(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "message/delete", 14) == 0) message_delete(ssl, &decrypted, lenDecrypted, pubkey);

	else if (memcmp(url, "private/update", 14) == 0) private_update(ssl, &decrypted, lenDecrypted, pubkey);
	else if (memcmp(url, "setting/limits", 14) == 0) setting_limits(ssl, &decrypted, lenDecrypted, pubkey);

	return 0;
}
