#define _GNU_SOURCE // for peercred

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <maxminddb.h>
#include <sodium.h>

#include "Include/Addr32.h"
#include "Include/Message.h"

#include "delivery.h"

#include "../Global.h"

static unsigned char accessKey_account[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage[AEM_LEN_ACCESSKEY];

void setAccessKey_account(const unsigned char * const newKey) {memcpy(accessKey_account, newKey, AEM_LEN_ACCESSKEY);}
void setAccessKey_storage(const unsigned char * const newKey) {memcpy(accessKey_storage, newKey, AEM_LEN_ACCESSKEY);}

__attribute__((warn_unused_result))
static uint16_t getCountryCode(const struct sockaddr * const sockAddr) {
	if (sockAddr == NULL) return 0;

	MMDB_s mmdb;
	int status = MMDB_open("GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb);
	if (status != MMDB_SUCCESS) {
		syslog(LOG_ERR, "getCountryCode: Can't open database: %s", MMDB_strerror(status));
		return 0;
	}

	MMDB_lookup_result_s mmdb_result = MMDB_lookup_sockaddr(&mmdb, sockAddr, &status);
	if (status != MMDB_SUCCESS) {
		syslog(LOG_ERR, "getCountryCode: libmaxminddb error: %s", MMDB_strerror(status));
		MMDB_close(&mmdb);
		return 0;
	}

	uint16_t ret = 0;
	if (mmdb_result.found_entry) {
		MMDB_entry_data_s entry_data;
		status = MMDB_get_value(&mmdb_result.entry, &entry_data, "country", "iso_code", NULL);

		if (status == MMDB_SUCCESS) {
			memcpy(&ret, entry_data.utf8_string, 2);
		} else {
			syslog(LOG_ERR, "getCountryCode: Error looking up the entry data: %s", MMDB_strerror(status));
		}
	} else syslog(LOG_ERR, "getCountryCode: No entry for the IP address was found");

	MMDB_close(&mmdb);
	return ret;
}

#include "../Common/UnixSocketClient.c"

static int accountSocket(const unsigned char command, const unsigned char * const msg, const size_t lenMsg) {
	const int sock = getUnixSocket("Account.sck");
	if (sock < 1) return -1;

	const size_t lenClear = 1 + lenMsg;
	unsigned char clear[lenClear];
	clear[0] = command;
	memcpy(clear + 1, msg, lenMsg);

	const ssize_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear;
	unsigned char encrypted[lenEncrypted];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear, encrypted, accessKey_account);

	if (send(sock, encrypted, lenEncrypted, 0) != lenEncrypted) {
		close(sock);
		return -1;
	}

	return sock;
}

static int storageSocket(const unsigned char * const msg, const size_t lenMsg) {
	const int sock = getUnixSocket("Storage.sck");
	if (sock < 1) return -1;

	const ssize_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenMsg;
	unsigned char encrypted[lenEncrypted];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, msg, lenMsg, encrypted, accessKey_storage);

	if (send(sock, encrypted, lenEncrypted, 0) != lenEncrypted) {
		close(sock);
		return -1;
	}

	return sock;
}

static int getPublicKey(const unsigned char * const addr32, unsigned char * const pubkey, const bool isShield) {
	const int sock = accountSocket(isShield ? AEM_MTA_GETPUBKEY_SHIELD : AEM_MTA_GETPUBKEY_NORMAL, addr32, 15);
	if (sock < 0) return -1;

	const ssize_t ret = recv(sock, pubkey, crypto_box_PUBLICKEYBYTES, 0);
	close(sock);
	return (ret == crypto_box_PUBLICKEYBYTES) ? 0 : -1;
}

void deliverMessage(char * const to, const size_t lenToTotal, const char * const from, const size_t lenFrom, const unsigned char * const msgBody, const size_t lenMsgBody, const struct sockaddr_in * const sockAddr, const int cs, const uint8_t tlsVer, unsigned char infoByte) {
	if (to == NULL || lenToTotal < 1 || from == NULL || lenFrom < 1 || msgBody == NULL || lenMsgBody < 1 || sockAddr == NULL) return;

	char *toStart = to;
	const char * const toEnd = to + lenToTotal;

	while(1) {
		char * const nextTo = memchr(toStart, '\n', toEnd - toStart);
		const size_t lenTo = ((nextTo != NULL) ? nextTo : toEnd) - toStart;
		if (lenTo < 1 || lenTo > 24) {syslog(LOG_ERR, "deliverMessage: Invalid receiver address length"); break;}
		if (lenTo == 24) infoByte |= AEM_INFOBYTE_ISSHIELD; else infoByte &= ~AEM_INFOBYTE_ISSHIELD;

		unsigned char addr32[15];
		addr32_store(addr32, toStart, lenTo);

		unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
		const int ret = getPublicKey(addr32, pubkey, lenTo == 24);
		if (ret != 0) {
			if (nextTo == NULL) break;
			toStart = nextTo + 1;
			continue;
		}

		const uint8_t attach = 0; // TODO
		const uint8_t spamByte = 0; // TODO
		const uint16_t countryCode = getCountryCode((struct sockaddr*)sockAddr);

		size_t bodyLen = lenMsgBody;
		unsigned char * const boxSet = makeMsg_Ext(pubkey, addr32, msgBody, &bodyLen, sockAddr->sin_addr.s_addr, cs, tlsVer, countryCode, attach, infoByte, spamByte);
		const size_t bsLen = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + bodyLen + crypto_box_SEALBYTES;

		if (boxSet == NULL || bsLen < 1 || bsLen % 1024 != 0) {
			syslog(LOG_ERR, "makeMsg_Ext failed (%zu)", bsLen);
			if (nextTo == NULL) break;
			toStart = nextTo + 1;
			continue;
		}

		// Deliver
		unsigned char cmd[1 + crypto_box_PUBLICKEYBYTES];
		cmd[0] = bsLen / 1024;
		memcpy(cmd + 1, pubkey, crypto_box_PUBLICKEYBYTES);

		const int stoSock = storageSocket(cmd, 1 + crypto_box_PUBLICKEYBYTES);
		if (stoSock >= 0) {
			if (send(stoSock, boxSet, bsLen, 0) != (ssize_t)bsLen)
				syslog(LOG_ERR, "Failed sending to Storage");
		}

		free(boxSet);
		close(stoSock);

		if (nextTo == NULL) break;
		toStart = nextTo + 1;
	}
}
