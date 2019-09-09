#include <string.h>
#include <stdint.h>
#include <time.h>

#include <mbedtls/ssl.h>
#include <sodium.h>

#include "Includes/CharToInt64.h"
#include "Includes/SixBit.h"

#include "Database.h"
#include "Message.h"
#include "https_common.h"

#include "https_post.h"

#define AEM_USERLEVEL_MIN 0
#define AEM_USERLEVEL_MAX 3

#define AEM_MAXMSGTOTALSIZE 1048576 // 1 MiB. Size of /api/account/browse response. TODO: Move this to config

static void send204(mbedtls_ssl_context * const ssl) {
	sendData(ssl,
		"HTTP/1.1 204 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=94672800\r\n"
		"Connection: close\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 199);
}

static int numDigits(double number) {
	int digits = 0;
	while (number > 1) {number /= 10; digits++;}
	return digits;
}

static int sendIntMsg(const unsigned char * const addrKey, const char * const addrFrom, const size_t lenFrom, const char * const addrTo, const size_t lenTo,
char * const * const decrypted, const size_t bodyBegin, const size_t lenDecrypted, const unsigned char * const sender_pk, const char senderCopy) {
	if (addrFrom == NULL || addrTo == NULL || lenFrom < 1 || lenTo < 1) return -1;

	unsigned char binFrom[18];
	int ret = addr2bin(addrFrom, lenFrom, binFrom);
	if (ret < 1) return -1;

	unsigned char binTo[18];
	ret = addr2bin(addrTo, lenTo, binTo);
	if (ret < 1) return -1;

	unsigned char recv_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char flags;
	ret = getPublicKeyFromAddress(binTo, recv_pk, addrKey, &flags);
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

// TODO: Support multiple pages
static void account_browse(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted) {
	if (lenDecrypted != 17 || memcmp(*decrypted, "AllEars:Web.Login", 17) != 0) {sodium_free(*decrypted); return;}
	sodium_free(*decrypted);

	unsigned char *noteData;
	unsigned char *addrData;
	unsigned char *gkData;
	const int lenNote = AEM_NOTEDATA_LEN + crypto_box_SEALBYTES;
	uint16_t lenAddr;
	uint16_t lenGk;
	uint8_t msgCount;
	uint8_t level;

	const int ret = getUserInfo(upk64, &level, &noteData, &addrData, &lenAddr, &gkData, &lenGk);
	if (ret != 0) return;

	const size_t lenAdmin = (level == AEM_USERLEVEL_MAX) ? AEM_ADMINDATA_LEN : 0;
	unsigned char *adminData;
	if (level == AEM_USERLEVEL_MAX) getAdminData(&adminData);

	const size_t lenMsg = (level == AEM_USERLEVEL_MAX) ? AEM_MAXMSGTOTALSIZE - AEM_ADMINDATA_LEN : AEM_MAXMSGTOTALSIZE;
	unsigned char * const msgData = getUserMessages(upk64, &msgCount, lenMsg);
	if (msgData == NULL) {free(addrData); free(noteData); free(gkData); if (level == AEM_USERLEVEL_MAX) {free(adminData);} return;}

	const size_t lenBody = 6 + lenNote + lenAddr + lenGk + lenAdmin + lenMsg;
	const size_t lenHead = 198 + numDigits(lenBody);
	const size_t lenResponse = lenHead + lenBody;

	char * const data = malloc(lenResponse);
	if (data == NULL) {free(addrData); free(noteData); free(gkData); if (level == AEM_USERLEVEL_MAX) {free(adminData);} return;}
	sprintf(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=94672800\r\n"
		"Connection: close\r\n"
		"Content-Length: %zd\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, lenBody);

	memcpy(data + lenHead + 0, &level,    1);
	memcpy(data + lenHead + 1, &msgCount, 1);
	memcpy(data + lenHead + 2, &lenAddr,  2);
	memcpy(data + lenHead + 4, &lenGk,    2);

	size_t s = lenHead + 6;
	memcpy(data + s, noteData,  lenNote); s += lenNote;
	memcpy(data + s, addrData,  lenAddr); s += lenAddr;
	memcpy(data + s, gkData,    lenGk);   s += lenGk;
	if (level == AEM_USERLEVEL_MAX) {memcpy(data + s, adminData, lenAdmin); s += lenAdmin;}
	memcpy(data + s, msgData,   lenMsg);  s += lenMsg;

	free(noteData);
	free(addrData);
	free(gkData);
	if (level == AEM_USERLEVEL_MAX) free(adminData);
	free(msgData);

	sendData(ssl, data, lenResponse);
	free(data);
}

static void account_create(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted) {
	if (lenDecrypted != crypto_box_PUBLICKEYBYTES) {sodium_free(*decrypted); return;}
	if (getUserLevel(upk64) != AEM_USERLEVEL_MAX) {sodium_free(*decrypted); return;}

	const int ret = addAccount((unsigned char*)*decrypted);
	sodium_free(*decrypted);
	if (ret == 0) send204(ssl);
}

static void account_delete(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted) {
	if (lenDecrypted != 16) {sodium_free(*decrypted); return;}
	if (getUserLevel(upk64) != AEM_USERLEVEL_MAX) {sodium_free(*decrypted); return;}

	unsigned char targetPk[8];
	int ret = sodium_hex2bin(targetPk, 8, *decrypted, 16, NULL, NULL, NULL);
	sodium_free(*decrypted);
	if (ret != 0) return;

	ret = destroyAccount(charToInt64(targetPk));
	if (ret == 0) send204(ssl);
}

static void account_update(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted) {
	if (lenDecrypted != 17) {sodium_free(*decrypted); return;}
	if (getUserLevel(upk64) != AEM_USERLEVEL_MAX) {sodium_free(*decrypted); return;}

	const int level = strtol(*decrypted + 16, NULL, 10);
	if (level < AEM_USERLEVEL_MIN || level > AEM_USERLEVEL_MAX) return;

	unsigned char targetPk[8];
	int ret = sodium_hex2bin(targetPk, 8, *decrypted, 16, NULL, NULL, NULL);
	sodium_free(*decrypted);
	if (ret != 0) return;

	ret = setAccountLevel(charToInt64(targetPk), level);
	if (ret == 0) send204(ssl);
}

static void address_create(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted, const unsigned char * const addrKey) {
	unsigned char addr[18];
	const bool isShield = (lenDecrypted == 6 && memcmp(*decrypted, "SHIELD", 6) == 0);

	if (isShield) {
		sodium_free(*decrypted);
		randombytes_buf(addr, 18);
		if (isNormalBinAddress(addr)) return;
	} else {
		if (lenDecrypted > 24) {sodium_free(*decrypted); return;}

		int ret = addr2bin(*decrypted, lenDecrypted, addr);
		sodium_free(*decrypted);
		if (ret < 1) return;
	}

	const int64_t hash = addressToHash(addr, addrKey);
	if (addAddress(upk64, hash, isShield) != 0) return;

	char data[226];
	memcpy(data,
		"HTTP/1.1 200 aem\r\n"
		"Tk: N\r\n"
		"Strict-Transport-Security: max-age=94672800; includeSubDomains\r\n"
		"Expect-CT: enforce; max-age=94672800\r\n"
		"Connection: close\r\n"
		"Content-Length: 26\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 200);
	memcpy(data + 200, &hash, 8);
	memcpy(data + 208, addr, 18);
	sendData(ssl, data, 226);
}

static void address_delete(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted) {
	if (lenDecrypted < 10) {free(*decrypted); return;}
	const int64_t hash = charToInt64(*decrypted);
	const bool isShield = ((*decrypted)[8] == 'S');

	const unsigned char * const addrData = (unsigned char*)((*decrypted) + 9);
	const size_t lenAddrData = lenDecrypted - 9;

	const int ret = deleteAddress(upk64, hash, isShield, addrData, lenAddrData);
	sodium_free(*decrypted);
	if (ret == 0) send204(ssl);
}

static void address_update(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted) {
	if (lenDecrypted < 1 || lenDecrypted % 9 != 0) {free(*decrypted); return;}

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

// Takes BodyBox from client and stores it
static void message_assign(mbedtls_ssl_context * const ssl, unsigned char * const upk, char * const * const decrypted, const size_t lenDecrypted) {
	if (lenDecrypted > (262146 + crypto_box_SEALBYTES) || (lenDecrypted - crypto_box_SEALBYTES - 1) % 1026 != 0) {sodium_free(*decrypted); return;} // 256 KiB max size; padded to nearest 1024 prior to encryption (2 first bytes store padding length)

	// TODO: Move to Message.c
	// HeadBox format for notes: [1B] SenderInfo, [4B] Timestamp (uint32_t), 36 bytes unused (zeroed)
	unsigned char header[AEM_HEADBOX_SIZE];
	bzero(header, AEM_HEADBOX_SIZE);

	if ((*decrypted)[0] == 'F') {
		header[0] |= AEM_FLAG_MSGTYPE_FILENOTE;
	} else if ((*decrypted)[0] == 'T') {
		header[0] |= AEM_FLAG_MSGTYPE_TEXTNOTE;
	} else {
		puts("[HTTPS] message_assign: Unrecognized type");
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

// Creates BodyBox from client's instructions and stores it
static void message_create(mbedtls_ssl_context * const ssl, const unsigned char * const upk, char * const * const decrypted, const size_t lenDecrypted, const unsigned char * const addrKey, const char * const domain, const size_t lenDomain) {
/* Format:
	(From)\n
	(To)\n
	(Title)\n
	(Body)
*/
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
	if (lenTo > lenDomain + 1 && addrTo[lenTo - lenDomain - 1] == '@' && memcmp(addrTo + lenTo - lenDomain, domain, lenDomain) == 0) {
		ret = sendIntMsg(addrKey, addrFrom, lenFrom, addrTo, lenTo - lenDomain - 1, decrypted, (endTo + 1) - *decrypted, lenDecrypted, upk, senderCopy);
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

static void message_delete(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted) {
	uint8_t ids[lenDecrypted]; // 1 byte per ID
	for (size_t i = 0; i < lenDecrypted; i++) {
		ids[i] = (uint8_t)((*decrypted)[i]);
	}

	const int ret = deleteMessages(upk64, ids, (int)lenDecrypted);
	sodium_free(*decrypted);
	if (ret == 0) send204(ssl);
}

static void storage_enaddr(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted) {
	if (lenDecrypted < 1) {free(*decrypted); return;}

	const int ret = updateAddress(upk64, (unsigned char*)(*decrypted), lenDecrypted);
	sodium_free(*decrypted);
	if (ret == 0) send204(ssl);
}

static void storage_engate(mbedtls_ssl_context * const ssl, const unsigned char * const upk, char * const * const decrypted, const size_t lenDecrypted, const unsigned char * const hashKey) {
	const int ret = updateGatekeeper(upk, *decrypted, lenDecrypted, hashKey);
	sodium_free(*decrypted);
	if (ret == 0) send204(ssl);
}

static void storage_ennote(mbedtls_ssl_context * const ssl, const int64_t upk64, char * const * const decrypted, const size_t lenDecrypted) {
	if (lenDecrypted != AEM_NOTEDATA_LEN + crypto_box_SEALBYTES) {sodium_free(*decrypted); return;}

	const int ret = updateNoteData(upk64, (unsigned char*)*decrypted);
	sodium_free(*decrypted);
	if (ret == 0) send204(ssl);
}

static char *openWebBox(const unsigned char * const post, const size_t lenPost, unsigned char * const upk, size_t * const lenDecrypted, const unsigned char * const ssk) {
	const size_t skipBytes = crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES;

	if (lenPost <= skipBytes) return NULL;

	unsigned char nonce[crypto_box_NONCEBYTES];
	memcpy(nonce, post, crypto_box_NONCEBYTES);

	memcpy(upk, post + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);

	const int64_t upk64 = charToInt64(upk);
	if (!upk64Exists(upk64)) return NULL;

	char * const decrypted = sodium_malloc(lenPost);
	if (decrypted == NULL) return NULL;

	const int ret = crypto_box_open_easy((unsigned char*)decrypted, post + skipBytes, lenPost - skipBytes, nonce, upk, ssk);
	if (ret != 0) {sodium_free(decrypted); return NULL;}

	sodium_mprotect_readonly(decrypted);
	*lenDecrypted = lenPost - skipBytes - crypto_box_MACBYTES;

	return decrypted;
}

void https_post(mbedtls_ssl_context * const ssl, const unsigned char * const ssk, const unsigned char * const addrKey, const char * const domain, const size_t lenDomain, const char * const url, const unsigned char * const post, const size_t lenPost) {
	unsigned char upk[crypto_box_PUBLICKEYBYTES];
	size_t lenDecrypted;
	char * const decrypted = openWebBox(post, lenPost, upk, &lenDecrypted, ssk);
	if (decrypted == NULL || lenDecrypted < 1) return;

	const int64_t upk64 = charToInt64(upk);

	if (memcmp(url, "account/browse", 14) == 0) return account_browse(ssl, upk64, &decrypted, lenDecrypted);

	if (memcmp(url, "account/create", 14) == 0) return account_create(ssl, upk64, &decrypted, lenDecrypted);
	if (memcmp(url, "account/delete", 14) == 0) return account_delete(ssl, upk64, &decrypted, lenDecrypted);
	if (memcmp(url, "account/update", 14) == 0) return account_update(ssl, upk64, &decrypted, lenDecrypted);

	if (memcmp(url, "address/create", 14) == 0) return address_create(ssl, upk64, &decrypted, lenDecrypted, addrKey);
	if (memcmp(url, "address/delete", 14) == 0) return address_delete(ssl, upk64, &decrypted, lenDecrypted);
	if (memcmp(url, "address/update", 14) == 0) return address_update(ssl, upk64, &decrypted, lenDecrypted);

	if (memcmp(url, "message/assign", 14) == 0) return message_assign(ssl, upk,   &decrypted, lenDecrypted);
	if (memcmp(url, "message/create", 14) == 0) return message_create(ssl, upk,   &decrypted, lenDecrypted, addrKey, domain, lenDomain);
	if (memcmp(url, "message/delete", 14) == 0) return message_delete(ssl, upk64, &decrypted, lenDecrypted);

	if (memcmp(url, "storage/enaddr", 14) == 0) return storage_enaddr(ssl, upk64, &decrypted, lenDecrypted);
	if (memcmp(url, "storage/engate", 14) == 0) return storage_engate(ssl, upk,   &decrypted, lenDecrypted, addrKey);
	if (memcmp(url, "storage/ennote", 14) == 0) return storage_ennote(ssl, upk64, &decrypted, lenDecrypted);
}
