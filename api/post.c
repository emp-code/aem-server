#include <ctype.h> // for islower
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

#include "Include/https_common.h"

#include "post.h"

#define AEM_MAXMSGTOTALSIZE 1048576 // 1 MiB. Size of /api/account/browse response. TODO: Move this to config

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

void https_pubkey(mbedtls_ssl_context * const ssl) {
	unsigned char data[225 + crypto_box_PUBLICKEYBYTES];

	memcpy(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Connection: close\r\n"
		"Cache-Control: no-store\r\n"
		"Content-Length: 32\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 225);

	crypto_scalarmult_base(data + 225, ssk);

	sendData(ssl, data, 225 + crypto_box_PUBLICKEYBYTES);
}

static void send204(mbedtls_ssl_context * const ssl) {
	sendData(ssl,
		"HTTP/1.1 204 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Connection: close\r\n"
		"Cache-Control: no-store\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Ignore: padded-to-253-bytes\r\n"
		"\r\n"
	, 253);
}

static int accountSocket(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const unsigned char command) {
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, "Account.sck");

	const int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed creating socket to Account");
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&sa, strlen(sa.sun_path) + sizeof(sa.sun_family)) == -1) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed connecting to Account");
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
		syslog(LOG_MAIL | LOG_NOTICE, "Failed creating socket to Storage");
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&sa, strlen(sa.sun_path) + sizeof(sa.sun_family)) == -1) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed connecting to Storage");
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
		close(sock);
		return -1;
	}

	return sock;
}

static void userViolation(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const int violation) {
	syslog(LOG_MAIL | LOG_NOTICE, "Violation");
	// ...
}

static void account_browse(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	sodium_free(*decrypted);
	if (lenDecrypted != 1) return;

	const int sock = accountSocket(pubkey, AEM_API_ACCOUNT_BROWSE);
	if (sock < 0) return;

	const size_t lenBody = 18 + AEM_LEN_PRIVATE + AEM_MAXMSGTOTALSIZE;

	char headers[300];
	sprintf(headers,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Connection: close\r\n"
		"Cache-Control: no-store\r\n"
		"Content-Length: %zd\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, lenBody);

	const size_t lenHead = strlen(headers);

	const size_t lenResponse = lenHead + lenBody;
	unsigned char response[lenResponse];
	bzero(response, lenResponse);

	memcpy(response, headers, lenHead);
	size_t offset = lenHead;

	if (recv(sock, response + offset, 13 + AEM_LEN_PRIVATE, 0) != 13 + AEM_LEN_PRIVATE) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with Account");
		sodium_memzero(response, lenResponse);
		close(sock);
		return;
	}

	offset += 13 + AEM_LEN_PRIVATE;

	// Admin Data
	if (response[lenHead + 12] == AEM_USERLEVEL_MAX) {
		if (recv(sock, response + offset, 35 * 1024, 0) != 35 * 1024) {
			syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with Account");
			sodium_memzero(response, lenResponse);
			close(sock);
			return;
		}

		offset += 35 * 1024;
	}

	close(sock);

	// Messages
	const int stoSock = storageSocket(pubkey, 0);
	if (stoSock > 0) {
		while(1) {
			unsigned char buf[131072];
			const ssize_t r = recv(stoSock, buf, 131072, 0);
			if (r < 1 || r % 1024 != 0) break;

			response[offset] = (r / 1024);
			offset++;
			memcpy(response + offset, buf, r);
			offset += r;

			send(stoSock, buf, 1, 0);
		}
	} else syslog(LOG_MAIL | LOG_NOTICE, "Failed stoSock");

	close(stoSock);
	sendData(ssl, response, lenResponse);
	sodium_memzero(response, lenResponse);
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
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	send204(ssl);
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
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	send204(ssl);
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
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	send204(ssl);
}

static void address_create(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != 13 && (lenDecrypted != 6 || memcmp(*decrypted, "SHIELD", 6) != 0)) {
		sodium_free(*decrypted);
		return;
	}

	const int sock = accountSocket(pubkey, AEM_API_ADDRESS_CREATE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed sending data to Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);

	if (lenDecrypted == 13) { // Normal
		send204(ssl);
		close(sock);
		return;
	}

	// Shield
	unsigned char data[253];
	memcpy(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Cache-Control: no-store\r\n"
		"Connection: close\r\n"
		"Content-Length: 28\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 225);

	if (
	   recv(sock, data + 225, 13, 0) != 13
	|| recv(sock, data + 238, 15, 0) != 15
	) {syslog(LOG_MAIL | LOG_NOTICE, "Failed receiving data from Account"); close(sock); return;}

	close(sock);

	sendData(ssl, data, 253);
}

static void address_delete(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != 13) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_ADDRESS_DELETE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	send204(ssl);
}

static void address_update(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted % 14 != 0) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_ADDRESS_UPDATE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	send204(ssl);
}

static void private_update(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != AEM_LEN_PRIVATE) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_PRIVATE_UPDATE);
	if (sock < 0) {sodium_free(*decrypted); return;}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	send204(ssl);
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
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with Account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	send204(ssl);
}

__attribute__((warn_unused_result))
static char *openWebBox(const unsigned char * const post, unsigned char * const pubkey, size_t * const lenDecrypted) {
	const size_t skipBytes = crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES;

	unsigned char nonce[crypto_box_NONCEBYTES];
	memcpy(nonce, post, crypto_box_NONCEBYTES);

	memcpy(pubkey, post + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);

//	if (pubkeyExists(pubkey)) return NULL; // XXX Important to re-enable

	char * const decrypted = sodium_malloc(AEM_HTTPS_POST_SIZE);
	if (decrypted == NULL) return NULL;

	const int ret = crypto_box_open_easy((unsigned char*)decrypted, post + skipBytes, AEM_HTTPS_POST_SIZE + crypto_box_MACBYTES, nonce, pubkey, ssk);
	if (ret != 0) {sodium_free(decrypted); return NULL;}
	sodium_mprotect_readonly(decrypted);

	uint16_t u16len;
	memcpy(&u16len, decrypted + AEM_HTTPS_POST_SIZE - 2, 2);
	*lenDecrypted = u16len;

	return decrypted;
}

void https_post(mbedtls_ssl_context * const ssl, const char * const url, const unsigned char * const post) {
	if (ssl == NULL || url == NULL || post == NULL) return;

	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	size_t lenDecrypted;

	char * const decrypted = openWebBox(post, pubkey, &lenDecrypted);
	if (decrypted == NULL || lenDecrypted < 1) return;

	if (memcmp(url, "account/browse", 14) == 0) return account_browse(ssl, &decrypted, lenDecrypted, pubkey);
	if (memcmp(url, "account/create", 14) == 0) return account_create(ssl, &decrypted, lenDecrypted, pubkey);
	if (memcmp(url, "account/delete", 14) == 0) return account_delete(ssl, &decrypted, lenDecrypted, pubkey);
	if (memcmp(url, "account/update", 14) == 0) return account_update(ssl, &decrypted, lenDecrypted, pubkey);

	if (memcmp(url, "address/create", 14) == 0) return address_create(ssl, &decrypted, lenDecrypted, pubkey);
	if (memcmp(url, "address/delete", 14) == 0) return address_delete(ssl, &decrypted, lenDecrypted, pubkey);
	if (memcmp(url, "address/update", 14) == 0) return address_update(ssl, &decrypted, lenDecrypted, pubkey);

//	if (memcmp(url, "message/assign", 14) == 0) return message_assign(ssl, &decrypted, lenDecrypted, pubkey);
//	if (memcmp(url, "message/create", 14) == 0) return message_create(ssl, &decrypted, lenDecrypted, pubkey);
//	if (memcmp(url, "message/delete", 14) == 0) return message_delete(ssl, &decrypted, lenDecrypted, pubkey);

	if (memcmp(url, "private/update", 14) == 0) return private_update(ssl, &decrypted, lenDecrypted, pubkey);

	if (memcmp(url, "setting/limits", 14) == 0) return setting_limits(ssl, &decrypted, lenDecrypted, pubkey);
}
