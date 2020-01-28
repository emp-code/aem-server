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
		"\r\n"
	, 224);
}

static int accountSocket(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const unsigned char command) {
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, "Account.sck");

	const int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed creating socket to allears-account");
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&sa, strlen(sa.sun_path) + sizeof(sa.sun_family)) == -1) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed connecting to allears-account");
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

/*
__attribute__((warn_unused_result))
static int sendIntMsg(const char * const addrFrom, const size_t lenFrom, const char * const addrTo, const size_t lenTo,
char * const * const decrypted, const size_t bodyBegin, const size_t lenDecrypted, const unsigned char * const sender_pk, const char senderCopy) {
	if (addrFrom == NULL || addrTo == NULL || lenFrom < 1 || lenTo < 1 || lenFrom > 24 || lenTo > 24) return -1;

	unsigned char binFrom[15];
	addr32_store(binFrom, addrFrom, lenFrom);

	unsigned char binTo[15];
	addr32_store(binTo, addrTo, lenTo);

	unsigned char recv_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char flags;
	int ret = getPublicKeyFromAddress(binTo, recv_pk, &flags);
	if (ret != 0 || !(flags & AEM_FLAGS_ADDR_ACC_INTMSG) || memcmp(recv_pk, sender_pk, crypto_box_PUBLICKEYBYTES) == 0) return -1;

	const int64_t sender_pk64 = charToInt64(sender_pk);
	const int memberLevel = getUserLevel(sender_pk64);
	if (memberLevel < AEM_USERLEVEL_MIN || memberLevel > AEM_USERLEVEL_MAX) return -1;

	size_t bodyLen = lenDecrypted - bodyBegin;
	unsigned char *boxSet = makeMsg_Int(recv_pk, binFrom, binTo, *decrypted + bodyBegin, &bodyLen, memberLevel);
	const size_t bsLen = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + bodyLen + crypto_box_SEALBYTES;
	if (boxSet == NULL) return -1;

	const int64_t recv_pk64 = charToInt64(recv_pk);
	ret = addUserMessage(recv_pk64, boxSet, bsLen);
	free(boxSet);
	if (ret != 0) return -1;

	if (senderCopy == 'Y') {
		bodyLen = lenDecrypted - bodyBegin;
		boxSet = makeMsg_Int(sender_pk, binFrom, binTo, *decrypted + bodyBegin, &bodyLen, memberLevel);
		if (boxSet == NULL) return -1;

		ret = addUserMessage(sender_pk64, boxSet, bsLen);
		free(boxSet);
		if (ret != 0) return -1;
	}

	return 0;
}
*/

/*
static void userViolation(const int64_t upk64, const int violation) {
	syslog(LOG_MAIL | LOG_NOTICE, "[System] Destroying account %lx for violation %x\n", upk64, violation);
	destroyAccount(upk64);
}
*/

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

	memcpy(response, headers, lenHead);
	size_t offset = lenHead;

	if (recv(sock, response + offset, 13 + AEM_LEN_PRIVATE, 0) != 13 + AEM_LEN_PRIVATE) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with allears-account");
		sodium_memzero(response, lenResponse);
		close(sock);
		return;
	}

	offset += 13 + AEM_LEN_PRIVATE;

	// Admin Data
	if (response[lenHead + 12] == AEM_USERLEVEL_MAX) {
		if (recv(sock, response + offset, 35 * 1024, 0) != 35 * 1024) {
			syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with allears-account");
			sodium_memzero(response, lenResponse);
			close(sock);
			return;
		}

		offset += 35 * 1024;
	}

	close(sock);

	// TODO: Messages

	sendData(ssl, response, lenResponse);
	sodium_memzero(response, lenResponse);
}

static void private_update(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != AEM_LEN_PRIVATE) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_PRIVATE_UPDATE);
	if (sock < 0) return;

	if (send(sock, decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with allears-account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	send204(ssl);
}

static void account_create(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_ACCOUNT_CREATE);
	if (sock < 0) return;

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		sodium_free(*decrypted);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
//		userViolation(pubkey, AEM_VIOLATION_ACCOUNT_CREATE);
		sodium_free(*decrypted);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
		sodium_free(*decrypted);
		return;
	}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with allears-account");
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
	if (sock < 0) return;

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		sodium_free(*decrypted);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
//		userViolation(pubkey, AEM_VIOLATION_ACCOUNT_DELETE);
		sodium_free(*decrypted);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
		sodium_free(*decrypted);
		return;
	}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with allears-account");
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
	if (sock < 0) return;

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		sodium_free(*decrypted);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
//		userViolation(pubkey, AEM_VIOLATION_ACCOUNT_UPDATE);
		sodium_free(*decrypted);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
		sodium_free(*decrypted);
		return;
	}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with allears-account");
		sodium_free(*decrypted);
		close(sock);
		return;
	}

	sodium_free(*decrypted);
	close(sock);

	send204(ssl);
}

/*
static void account_delete(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const int64_t upk64) {
	if (lenDecrypted != 8) {sodium_free(*decrypted); return;}

	const int64_t target64 = charToInt64(*decrypted);
	sodium_free(*decrypted);

	if (upk64 != target64 && getUserLevel(upk64) != AEM_USERLEVEL_MAX) {
		userViolation(upk64, AEM_VIOLATION_ACCOUNT_DELETE);
		return;
	}

	const int ret = destroyAccount(target64);
	if (ret == 0) send204(ssl);
}
*/

/*
static void account_update(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const int64_t upk64) {
	if (lenDecrypted != 9) {sodium_free(*decrypted); return;}

	if (getUserLevel(upk64) != AEM_USERLEVEL_MAX) {
		userViolation(upk64, AEM_VIOLATION_ACCOUNT_UPDATE);
		sodium_free(*decrypted);
		return;
	}

	const int64_t target64 = charToInt64(*decrypted);
	const uint8_t level = (*decrypted)[8];
	sodium_free(*decrypted);

	if (level > AEM_USERLEVEL_MAX || upk64 == target64) return;

	const int ret = setAccountLevel(target64, level);
	if (ret == 0) send204(ssl);
}
*/

/*
static void address_create(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const int64_t upk64) {
	unsigned char addr[15];
	const bool isShield = (lenDecrypted == 6 && memcmp(*decrypted, "SHIELD", 6) == 0);

	if (isShield) {
		sodium_free(*decrypted);
		randombytes_buf(addr, 15);
		addr[0] &= 7; // Clear the first five bits (7=4+2+1)
	} else {
		if (lenDecrypted > 24 || (lenDecrypted == 24 && (*decrypted)[0] == '5')) {sodium_free(*decrypted); return;}

		for (size_t i = 0; i < lenDecrypted; i++) {
			if (!islower((*decrypted)[i]) && !isdigit((*decrypted)[i])) {
				sodium_free(*decrypted);
				return;
			}
		}

		addr32_store(addr, *decrypted, lenDecrypted);
		sodium_free(*decrypted);
	}

	const int64_t hash = addressToHash(addr);
	if (addAddress(upk64, hash, isShield) != 0) return;

	char data[248];
	memcpy(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=99999999\r\n"
		"Cache-Control: no-store\r\n"
		"Connection: close\r\n"
		"Content-Length: 23\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 225);
	memcpy(data + 225, &hash, 8);
	memcpy(data + 233, addr, 15);

	sendData(ssl, data, 248);
}
*/

/*
static void address_delete(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const int64_t upk64) {
	if (lenDecrypted < 10) {free(*decrypted); return;}
	const int64_t hash = charToInt64(*decrypted);
	const bool isShield = ((*decrypted)[8] == 'S');

	const unsigned char * const addrData = (unsigned char*)((*decrypted) + 9);
	const size_t lenAddrData = lenDecrypted - 9;

	const int ret = deleteAddress(upk64, hash, isShield, addrData, lenAddrData);
	sodium_free(*decrypted);
	if (ret == 0) send204(ssl);
}
*/

/*
static void address_update(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const int64_t upk64) {
	if (lenDecrypted % 9 != 0) {free(*decrypted); return;}

	const unsigned int addressCount = lenDecrypted / 9; // unsigned to avoid GCC warning
	unsigned char addrFlags[addressCount];
	int64_t addrHash[addressCount];

	for (unsigned int i = 0; i < addressCount; i++) {
		memcpy(addrFlags + i, (*decrypted) + i * 9, 1);
		memcpy(addrHash + i, (*decrypted) + i * 9 + 1, 8);
	}

	sodium_free(*decrypted);

	const int ret = updateAddressSettings(upk64, addrHash, addrFlags, addressCount);
	if (ret == 0) send204(ssl);
}
*/

/*
// Takes BodyBox from client and stores it
static void message_assign(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, unsigned char * const upk) {
	if ((lenDecrypted - crypto_box_SEALBYTES - 3) % 1024 != 0) {
		sodium_free(*decrypted);
		return;
	}

	// TODO: Move to Message.c
	// HeadBox format for notes: [1B] SenderInfo, [4B] Timestamp (uint32_t), 36 bytes unused (zeroed)
	unsigned char header[AEM_HEADBOX_SIZE];
	bzero(header, AEM_HEADBOX_SIZE);

	if ((*decrypted)[0] == 'F') {
		header[0] |= AEM_FLAG_MSGTYPE_FILENOTE;
	} else if ((*decrypted)[0] == 'T') {
		header[0] |= AEM_FLAG_MSGTYPE_TEXTNOTE;
	} else {
		syslog(LOG_MAIL | LOG_NOTICE, "message_assign: Unrecognized type");
		sodium_free(*decrypted);
		return;
	}

	const uint32_t t = (uint32_t)time(NULL);
	memcpy(header + 1, &t, 4);

	const size_t bsLen = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + lenDecrypted - 1;
	unsigned char * const boxset = malloc(bsLen);
	if (boxset == NULL) {sodium_free(*decrypted); return;}

	crypto_box_seal(boxset, header, AEM_HEADBOX_SIZE, upk);
	memcpy(boxset + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES, (*decrypted) + 1, lenDecrypted - 1);
	sodium_free(*decrypted);

	const int ret = addUserMessage(charToInt64(upk), boxset, bsLen);
	free(boxset);
	if (ret == 0) send204(ssl);
}
*/

// Creates BodyBox from client's instructions and stores it
//static void message_create(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char * const upk) {
/* Format:
	(From)\n
	(To)\n
	(Title)\n
	(Body)
*//*
	const char senderCopy = *decrypted[0];

	const char *addrFrom = *decrypted + 1;
	const char *endFrom = strchr(addrFrom, '\n');
	if (endFrom == NULL) {sodium_free(*decrypted); return;}
	const size_t lenFrom = endFrom - addrFrom;

	const char *addrTo = endFrom + 1;
	const char *endTo = strchr(addrTo, '\n');
	if (endTo == NULL) {sodium_free(*decrypted); return;}
	const size_t lenTo = endTo - addrTo;

	int ret;
	if (memchr(addrTo, '@', lenTo) == NULL) {
		ret = sendIntMsg(addrFrom, lenFrom, addrTo, lenTo, decrypted, (endTo + 1) - *decrypted, lenDecrypted, upk, senderCopy);
	} else {
		const char * const domainAt = strchr(addrTo, '@');
		if (domainAt == NULL) {
			sodium_free(*decrypted);
			return;
		}

		const size_t lenExtDomain = lenTo - (domainAt - addrTo) - 1;
		char extDomain[lenExtDomain + 1];
		memcpy(extDomain, domainAt + 1, lenExtDomain);
		extDomain[lenExtDomain] = '\0';

		// TODO: ExtMsg (email)
		sodium_free(*decrypted);
		return;
	}

	sodium_free(*decrypted);
	if (ret == 0) send204(ssl);
}
*/

/*
static void message_delete(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const int64_t upk64) {
	uint8_t ids[lenDecrypted]; // 1 byte per ID
	for (size_t i = 0; i < lenDecrypted; i++) {
		ids[i] = (uint8_t)((*decrypted)[i]);
	}

	const int ret = deleteMessages(upk64, ids, (int)lenDecrypted);
	sodium_free(*decrypted);
	if (ret == 0) send204(ssl);
}
*/

static void setting_limits(mbedtls_ssl_context * const ssl, char * const * const decrypted, const size_t lenDecrypted, const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	if (lenDecrypted != 12) {sodium_free(*decrypted); return;}

	const int sock = accountSocket(pubkey, AEM_API_SETTING_LIMITS);
	if (sock < 0) return;

	unsigned char response;
	if (recv(sock, &response, 1, 0) != 1) {
		sodium_free(*decrypted);
		return;
	} else if (response == AEM_ACCOUNT_RESPONSE_VIOLATION) {
//		userViolation(pubkey, AEM_VIOLATION_SETTING_LIMITS);
		sodium_free(*decrypted);
		return;
	} else if (response != AEM_ACCOUNT_RESPONSE_OK) {
		sodium_free(*decrypted);
		return;
	}

	if (send(sock, *decrypted, lenDecrypted, 0) != (ssize_t)lenDecrypted) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed communicating with allears-account");
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
/*
	if (memcmp(url, "address/create", 14) == 0) return address_create(ssl, &decrypted, lenDecrypted, pubkey);
	if (memcmp(url, "address/delete", 14) == 0) return address_delete(ssl, &decrypted, lenDecrypted, pubkey);
	if (memcmp(url, "address/update", 14) == 0) return address_update(ssl, &decrypted, lenDecrypted, pubkey);

	if (memcmp(url, "message/assign", 14) == 0) return message_assign(ssl, &decrypted, lenDecrypted, pubkey);
	if (memcmp(url, "message/create", 14) == 0) return message_create(ssl, &decrypted, lenDecrypted, pubkey);
	if (memcmp(url, "message/delete", 14) == 0) return message_delete(ssl, &decrypted, lenDecrypted, pubkey);
*/
	if (memcmp(url, "private/update", 14) == 0) return private_update(ssl, &decrypted, lenDecrypted, pubkey);

	if (memcmp(url, "setting/limits", 14) == 0) return setting_limits(ssl, &decrypted, lenDecrypted, pubkey);
}
