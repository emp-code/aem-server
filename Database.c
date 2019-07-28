#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <endian.h>

#include <sodium.h>
#include <sqlite3.h>

#include "IntMsg.h"

#include "Includes/SixBit.h"

#include "Database.h"

#define AEM_DB_BUSY_TIMEOUT 15000 // milliseconds

#define AEM_PATH_DB_MESSAGES "/Data/Messages.aed"
#define AEM_PATH_DB_USERS  "/Data/Users.aed"

#define BIT_SET(a,b) ((a) |= (1ULL<<(b)))

static void dbSettings(sqlite3 *db) {
	sqlite3_exec(db, "PRAGMA temp_store=MEMORY", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA secure_delete=true", NULL, NULL, NULL);
	sqlite3_busy_timeout(db, AEM_DB_BUSY_TIMEOUT);
}

int64_t addressToHash(const unsigned char addr[18], const unsigned char hashKey[16]) {
	unsigned char hash16[16];
	crypto_generichash(hash16, 16, addr, 18, hashKey, 16);
//	if (crypto_pwhash(hash16, 16, (char*)addr, 18, hashKey, 3 /*OpsLimit*/, 67108864 /*MemLimit*/, crypto_pwhash_ALG_ARGON2ID13) != 0) return 0;

	int64_t result;
	memcpy(&result, hash16, 8);
	return result;
}

int64_t gkHash(const unsigned char *in, const size_t len, const int64_t upk64, const unsigned char hashKey[16]) {
	unsigned char saltyKey[24];
	memcpy(saltyKey, &upk64, 8);
	memcpy(saltyKey + 8, hashKey, 16);

	unsigned char hash16[16];
	crypto_generichash(hash16, 16, in, len, saltyKey, 24);
//	if (crypto_pwhash(hash16, 16, (char*)in, len, saltyKey, 3 /*OpsLimit*/, 67108864 /*MemLimit*/, crypto_pwhash_ALG_ARGON2ID13) != 0) return 0;

	int64_t result;
	memcpy(&result, hash16, 8);
	return result;
}

int getPublicKeyFromAddress(const unsigned char addr[18], unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char hashKey[16]) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT publickey FROM userdata WHERE upk64=(SELECT upk64 FROM address WHERE hash=?)", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, addressToHash(addr, hashKey));

	ret = sqlite3_step(query);
	if (ret != SQLITE_ROW || sqlite3_column_bytes(query, 0) != crypto_box_PUBLICKEYBYTES) {sqlite3_finalize(query); sqlite3_close_v2(db); return -1;}

	memcpy(pk, sqlite3_column_blob(query, 0), crypto_box_PUBLICKEYBYTES);

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return 0;
}

int getUserLevel(const int64_t upk64) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT level FROM userdata WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) return -1;

	sqlite3_bind_int64(query, 1, upk64);
	if (sqlite3_step(query) != SQLITE_ROW) {sqlite3_finalize(query); sqlite3_close_v2(db); return -1;}

	const int level = sqlite3_column_int(query, 0);

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return level;
}

int getUserInfo(const int64_t upk64, uint8_t * const level, unsigned char ** const noteData, unsigned char ** const addrData, uint16_t * const lenAddr, unsigned char ** const gkData, uint16_t * const lenGk) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT level, notedata, addrdata, gkdata FROM userdata WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) return -1;

	sqlite3_bind_int64(query, 1, upk64);
	if (sqlite3_step(query) != SQLITE_ROW) {sqlite3_finalize(query); sqlite3_close_v2(db); return -1;}

	*level = sqlite3_column_int(query, 0);

	*noteData = calloc(AEM_NOTEDATA_LEN + crypto_box_SEALBYTES, 1);
	if (*noteData == NULL) {sqlite3_finalize(query); sqlite3_close_v2(db); return -1;}
	memcpy(*noteData, sqlite3_column_blob(query, 1), AEM_NOTEDATA_LEN + crypto_box_SEALBYTES);

	*lenAddr = sqlite3_column_bytes(query, 2);
	*addrData = malloc(*lenAddr);
	if (*addrData == NULL) {sqlite3_finalize(query); sqlite3_close_v2(db); free(noteData); return -1;}
	memcpy(*addrData, sqlite3_column_blob(query, 2), *lenAddr);

	*lenGk = sqlite3_column_bytes(query, 3);
	*gkData = malloc(*lenGk);
	if (*gkData == NULL) {sqlite3_finalize(query); sqlite3_close_v2(db); free(noteData); free(*addrData); return -1;}
	memcpy(*gkData, sqlite3_column_blob(query, 3), *lenGk);

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return 0;
}

int getAdminData(unsigned char ** const adminData) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	*adminData = calloc(AEM_ADMINDATA_LEN, 1);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT publickey, level FROM userdata LIMIT 1024", -1, &query, NULL);
	if (ret != SQLITE_OK) return -1;

	int userCount = 0;
	while (sqlite3_step(query) == SQLITE_ROW) {
		memcpy(*adminData + (userCount * 9), sqlite3_column_blob(query, 0), 8);

		unsigned char memberInfo = 0x0;
		switch(sqlite3_column_int(query, 1)) {
		case 3:
			BIT_SET(memberInfo, 0);
			BIT_SET(memberInfo, 1);
			break;
		case 2:
			BIT_SET(memberInfo, 1);
			break;
		case 1:
			BIT_SET(memberInfo, 0);
			break;
		}

		*(*adminData + (userCount * 9) + 8) = memberInfo;
		userCount++;
	}

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return 0;
}

unsigned char *getUserMessages(const int64_t upk64, uint8_t * const msgCount, const size_t maxSize) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_MESSAGES, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return NULL;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT msg,row_number FROM (SELECT rowid,row_number() OVER (ORDER BY rowid ASC) AS row_number FROM msg WHERE upk64=? ORDER BY rowid DESC) JOIN msg ON msg.rowid=rowid LIMIT 255", -1, &query, NULL);

	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return NULL;}
	sqlite3_bind_int64(query, 1, upk64);

	unsigned char *data = calloc(maxSize, 1);
	size_t totalSize = 0;
	*msgCount = 0;

	while (sqlite3_step(query) == SQLITE_ROW && *msgCount < 255) {
		const size_t sz = sqlite3_column_bytes(query, 0);
		if (sz < 5) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

		if (totalSize + sz > maxSize) break;

		const size_t msgLen = sz - AEM_INTMSG_HEADERSIZE - (crypto_box_SEALBYTES * 2); // Length of decrypted Body part
		if ((msgLen - 2) % 1024 != 0) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

		int sizeFactor = ((msgLen - 2) / 1024) - 1; // 0 = 1KiB, 255=256KiB
		if (sizeFactor > 255) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

		data[totalSize + 0] = sqlite3_column_int(query, 1);
		data[totalSize + 1] = sizeFactor;
		memcpy(data + totalSize + 2, sqlite3_column_blob(query, 0), sz);
		totalSize += sz + 2;
		(*msgCount)++;
	}

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return data;
}

int addUserMessage(const int64_t upk64, const unsigned char *msgData, const size_t msgLen) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_MESSAGES, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO msg (upk64, msg) VALUES (?, ?)", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, upk64);
	sqlite3_bind_blob(query, 2, msgData, msgLen, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int deleteAddress(const int64_t upk64, const int64_t hash, const unsigned char *addrData, const size_t lenAddrData) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "DELETE FROM address WHERE hash=? AND upk64=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, hash);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	if (ret != SQLITE_DONE) {sqlite3_close_v2(db); return -1;}

	ret = sqlite3_prepare_v2(db, "UPDATE userdata SET addrdata=? WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, addrData, lenAddrData, SQLITE_STATIC);
	sqlite3_bind_int64(query, 2, upk64);

	sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return 0;
}

// Format: item1\nitem2\n...
int updateGatekeeper(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], char * const gkData, const size_t lenGkData, const unsigned char hashKey[16]) {
	if (lenGkData < 1) return -1;
	if (gkData[lenGkData - 1] != '\n') return -1;

	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	int64_t upk64;
	memcpy(&upk64, ownerPk, 8);

	sqlite3_stmt *query;
	sqlite3_prepare_v2(db, "DELETE FROM gatekeeper WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, upk64);
	sqlite3_step(query);
	sqlite3_finalize(query);

	char *lf = gkData;
	while (lf != NULL) {
		char *next = strchr(lf + 1, '\n');
		const size_t len = next - lf - 1;
		if (*lf == '\n') lf++;

		const size_t lenGksb = lenToSixBit(len);
		unsigned char* gkSixBit = textToSixBit(lf, len);
		if (memchr(gkSixBit, '?', lenGksb) == NULL) {
			sqlite3_prepare_v2(db, "INSERT INTO gatekeeper (hash, upk64) VALUES (?, ?)", -1, &query, NULL);
			sqlite3_bind_int64(query, 1, gkHash(gkSixBit, lenGksb, upk64, hashKey));
			sqlite3_bind_int64(query, 2, upk64);
			sqlite3_step(query);
			sqlite3_finalize(query);
		}
		free(gkSixBit);

		lf = next;
		if (lenGkData - (next - gkData) < 2) break;
	}

	unsigned char *ciphertext = malloc(lenGkData + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, (unsigned char*)gkData, lenGkData, ownerPk);

	sqlite3_prepare_v2(db, "UPDATE userdata SET gkdata=? WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, ciphertext, lenGkData + crypto_box_SEALBYTES, free);
	sqlite3_bind_int64(query, 2, upk64);
	sqlite3_step(query);
	sqlite3_finalize(query);

	sqlite3_close_v2(db);
	return 0;
}

int deleteMessages(const int64_t upk64, const int ids[], const int count) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_MESSAGES, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT rowid,row_number() OVER (ORDER BY rowid ASC) AS row_number FROM msg WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}
	sqlite3_bind_int64(query, 1, upk64);

	int rowCount = 0;
	int rowIds[count];
	for (int i = 0; rowCount < count; i++) {
		if (sqlite3_step(query) != SQLITE_ROW) {
			sqlite3_finalize(query);
			sqlite3_close_v2(db);
			return -1;
		}

		int deleteRowId = -1;
		for (int i = 0; i < count; i++) {
			if (ids[i] == sqlite3_column_int(query, 1)) {
				deleteRowId = sqlite3_column_int(query, 0);
				break;
			}
		}

		if (deleteRowId == -1) continue;

		rowIds[rowCount] = deleteRowId;
		rowCount++;
	}

	sqlite3_finalize(query);

	for (int i = 0; i < rowCount; i++) {
		ret = sqlite3_prepare_v2(db, "DELETE FROM msg WHERE rowid=? AND upk64=?", -1, &query, NULL);
		sqlite3_bind_int(query, 1, rowIds[i]);
		sqlite3_bind_int64(query, 2, upk64);
		sqlite3_step(query);
		sqlite3_finalize(query);
	}

	sqlite3_close_v2(db);
	return 0;
}

int updateNoteData(const int64_t upk64, const unsigned char *noteData) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "UPDATE userdata SET notedata=? WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, noteData, AEM_NOTEDATA_LEN + crypto_box_SEALBYTES, SQLITE_STATIC);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int updateAddress(const int64_t upk64, const unsigned char *addrData, const size_t lenAddrData) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "UPDATE userdata SET addrdata=? WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, addrData, lenAddrData, SQLITE_STATIC);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int addAddress(const int64_t upk64, const int64_t hash) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO address (hash, upk64) VALUES (?, ?)", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, hash);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int addAccount(const unsigned char pk[crypto_box_PUBLICKEYBYTES]) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	unsigned char zero[AEM_NOTEDATA_LEN];
	sodium_memzero(zero, AEM_NOTEDATA_LEN);

	unsigned char ciphertext_notedata[AEM_NOTEDATA_LEN + crypto_box_SEALBYTES];
	unsigned char ciphertext_empty[crypto_box_SEALBYTES];
	crypto_box_seal(ciphertext_notedata, zero, AEM_NOTEDATA_LEN, pk);
	crypto_box_seal(ciphertext_empty, NULL, 0, pk);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO userdata (upk64, publickey, level, notedata, addrdata, gkdata) VALUES (?,?,?,?,?,?)", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_finalize(query); sqlite3_close_v2(db); return -1;}

	int64_t upk64;
	memcpy(&upk64, pk, 8);

	sqlite3_bind_int64(query, 1, upk64);
	sqlite3_bind_blob(query, 2, pk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);
	sqlite3_bind_int(query, 3, 0);
	sqlite3_bind_blob(query, 4, ciphertext_notedata, AEM_NOTEDATA_LEN + crypto_box_SEALBYTES, SQLITE_STATIC);
	sqlite3_bind_blob(query, 5, ciphertext_empty, crypto_box_SEALBYTES, SQLITE_STATIC);
	sqlite3_bind_blob(query, 6, ciphertext_empty, crypto_box_SEALBYTES, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int setAccountLevel(const char pk_hex[16], const int level) {
	if (level < 0 || level > 3) return -1;

	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;
	sqlite3_prepare_v2(db, "UPDATE userdata SET level=? WHERE lower(substr(hex(publickey), 1, 16))=?", -1, &query, NULL);
	sqlite3_bind_int(query, 1, level);
	sqlite3_bind_text(query, 2, pk_hex, 16, SQLITE_STATIC);

	const int retval = (sqlite3_step(query) == SQLITE_DONE) ? 0 : -1;
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return retval;
}

int destroyAccount(const int64_t upk64) {
	int retval = 0;

	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);

	sqlite3_stmt *query;

	sqlite3_prepare_v2(db, "DELETE FROM userdata WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, upk64);
	if (sqlite3_step(query) != SQLITE_DONE) retval = -1;
	sqlite3_finalize(query);

	sqlite3_prepare_v2(db, "DELETE FROM address WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, upk64);
	if (sqlite3_step(query) != SQLITE_DONE) retval = -1;
	sqlite3_finalize(query);

	sqlite3_prepare_v2(db, "DELETE FROM gatekeeper WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, upk64);
	if (sqlite3_step(query) != SQLITE_DONE) retval = -1;
	sqlite3_finalize(query);

	sqlite3_close_v2(db);

	if (sqlite3_open_v2(AEM_PATH_DB_MESSAGES, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;
	dbSettings(db);
	sqlite3_prepare_v2(db, "DELETE FROM msg WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, upk64);
	if (sqlite3_step(query) != SQLITE_DONE) retval = -1;
	sqlite3_finalize(query);
	sqlite3_close_v2(db);

	return retval;
}
