#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include <sodium.h>
#include <sqlite3.h>

#include "Message.h"

#include "Includes/SixBit.h"

#include "Database.h"

#define AEM_ADDRESS_ARGON2_OPSLIMIT 3
#define AEM_ADDRESS_ARGON2_MEMLIMIT 67108864

#define AEM_DB_BUSY_TIMEOUT 15000 // milliseconds

#define AEM_PATH_DB_MESSAGES "/Messages.aed"
#define AEM_PATH_DB_USERS  "/Users.aed"

#define BIT_SET(a,b) ((a) |= (1ULL<<(b)))

static sqlite3 *openDb(const char * const path, const int flags) {
	sqlite3 *db;
	if (sqlite3_open_v2(path, &db, flags, NULL) != SQLITE_OK) return NULL;

	sqlite3_exec(db, "PRAGMA temp_store=MEMORY", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA secure_delete=true", NULL, NULL, NULL);
	sqlite3_busy_timeout(db, AEM_DB_BUSY_TIMEOUT);

	return db;
}

unsigned char *addr2bin(const char * const c, const size_t len) {
	if (len <= 24) {
		char d[len];
		for (size_t i = 0; i < len; i++) {
			if (isupper(c[i]))
				d[i] = tolower(c[i]);
			else if (isalnum(c[i]) || c[i] == '.' || c[i] == '-')
				d[i] = c[i];
			else
				return NULL;
		}

		return textToSixBit(d, len, 18);
	}

	if (len != 36) return NULL;

	// Shield addresses are encoded in hex
	for (int i = 0; i < 36; i++) {
		if (!((c[i] >= '0' && c[i] <= '9') || (c[i] >= 'a' && c[i] <= 'f'))) return NULL;
	}

	unsigned char bin[18];
	size_t binLen;
	sodium_hex2bin(bin, 18, c, 36, NULL, &binLen, NULL);
	if (binLen != 18) return NULL;
	unsigned char * const binm = malloc(18);
	memcpy(binm, bin, 18);
	return binm;
}

int64_t addressToHash(const unsigned char * const addr, const unsigned char * const addrKey) {
	unsigned char hash16[16];
	if (crypto_pwhash(hash16, 16, (char*)addr, 18, addrKey, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) return 0;
	return *((int64_t*)hash16);
}

int64_t gkHash(const unsigned char * const in, const size_t len, const int64_t upk64, const unsigned char * const hashKey) {
	unsigned char saltyKey[24];
	memcpy(saltyKey, &upk64, 8);
	memcpy(saltyKey + 8, hashKey, 16);

	unsigned char hash16[16];
	crypto_generichash(hash16, 16, in, len, saltyKey, 24);
//	if (crypto_pwhash(hash16, 16, (char*)in, len, saltyKey, 3 /*OpsLimit*/, 67108864 /*MemLimit*/, crypto_pwhash_ALG_ARGON2ID13) != 0) return 0;
	return *((int64_t*)hash16);
}

bool upk64Exists(const int64_t upk64) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return false;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT 1 FROM userdata WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) return false;
	sqlite3_bind_int64(query, 1, upk64);

	ret = sqlite3_step(query);
	const bool retval = (ret == SQLITE_ROW);

	sqlite3_finalize(query);
	sqlite3_close_v2(db);

	return retval;
}

int getPublicKeyFromAddress(const unsigned char * const addr, unsigned char * const pk, const unsigned char * const addrKey) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT publickey FROM userdata WHERE upk64=(SELECT upk64 FROM address WHERE hash=?)", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, addressToHash(addr, addrKey));

	ret = sqlite3_step(query);
	if (ret != SQLITE_ROW || sqlite3_column_bytes(query, 0) != crypto_box_PUBLICKEYBYTES) {
		sqlite3_finalize(query);
		sqlite3_close_v2(db);
		return -1;
	}

	memcpy(pk, sqlite3_column_blob(query, 0), crypto_box_PUBLICKEYBYTES);

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return 0;
}

int getUserLevel(const int64_t upk64) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return -1;

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
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return -1;

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
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return -1;

	*adminData = calloc(AEM_ADMINDATA_LEN, 1);

	sqlite3_stmt *query;
	const int ret = sqlite3_prepare_v2(db, "SELECT publickey, level FROM userdata LIMIT 1024", -1, &query, NULL);
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
	sqlite3 * const db = openDb(AEM_PATH_DB_MESSAGES, SQLITE_OPEN_READONLY);
	if (db == NULL) return NULL;

	sqlite3_stmt *query;
	const int ret = sqlite3_prepare_v2(db, "SELECT msg,row_number FROM (SELECT rowid,row_number() OVER (ORDER BY rowid ASC) AS row_number FROM msg WHERE upk64=? ORDER BY rowid DESC) JOIN msg ON msg.rowid=rowid LIMIT 255", -1, &query, NULL);

	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return NULL;}
	sqlite3_bind_int64(query, 1, upk64);

	unsigned char * const data = calloc(maxSize, 1);
	size_t totalSize = 0;
	*msgCount = 0;

	while (sqlite3_step(query) == SQLITE_ROW && *msgCount < 255) {
		const size_t sz = sqlite3_column_bytes(query, 0);
		if (sz < 5) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

		if (totalSize + sz > maxSize) break;

		const size_t msgLen = sz - AEM_HEADBOX_SIZE - (crypto_box_SEALBYTES * 2); // Length of decrypted Body part
		if ((msgLen - 2) % 1024 != 0) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

		const int sizeFactor = ((msgLen - 2) / 1024) - 1; // 0 = 1KiB, 255=256KiB
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

int addUserMessage(const int64_t upk64, const unsigned char * const msgData, const size_t msgLen) {
	sqlite3 * const db = openDb(AEM_PATH_DB_MESSAGES, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO msg (upk64, msg) VALUES (?, ?)", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, upk64);
	sqlite3_bind_blob(query, 2, msgData, msgLen, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int deleteAddress(const int64_t upk64, const int64_t hash, const unsigned char * const addrData, const size_t lenAddrData) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

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
int updateGatekeeper(const unsigned char * const ownerPk, char * const gkData, const size_t lenGkData, const unsigned char * const hashKey) {
	if (lenGkData < 1) return -1;
	if (gkData[lenGkData - 1] != '\n') return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	int64_t upk64;
	memcpy(&upk64, ownerPk, 8);

	sqlite3_stmt *query;
	sqlite3_prepare_v2(db, "DELETE FROM gatekeeper WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, upk64);
	sqlite3_step(query);
	sqlite3_finalize(query);

	const char *lf = gkData;
	while (lf != NULL) {
		char * const next = strchr(lf + 1, '\n');
		const size_t len = next - lf - 1;
		if (*lf == '\n') lf++;

		const size_t lenGksb = lenToSixBit(len);
		unsigned char * const gkSixBit = textToSixBit(lf, len, 0);
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

	unsigned char * const ciphertext = malloc(lenGkData + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, (unsigned char*)gkData, lenGkData, ownerPk);

	sqlite3_prepare_v2(db, "UPDATE userdata SET gkdata=? WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, ciphertext, lenGkData + crypto_box_SEALBYTES, free);
	sqlite3_bind_int64(query, 2, upk64);
	sqlite3_step(query);
	sqlite3_finalize(query);

	sqlite3_close_v2(db);
	return 0;
}

int deleteMessages(const int64_t upk64, const uint8_t * const ids, const int count) {
	sqlite3 * const db = openDb(AEM_PATH_DB_MESSAGES, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

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

int updateNoteData(const int64_t upk64, const unsigned char * const noteData) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "UPDATE userdata SET notedata=? WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, noteData, AEM_NOTEDATA_LEN + crypto_box_SEALBYTES, SQLITE_STATIC);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int updateAddress(const int64_t upk64, const unsigned char * const addrData, const size_t lenAddrData) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

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
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO address (hash, upk64) VALUES (?, ?)", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, hash);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int addAccount(const unsigned char * const pk) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return false;

	unsigned char zero[AEM_NOTEDATA_LEN];
	sodium_memzero(zero, AEM_NOTEDATA_LEN);

	unsigned char ciphertext_notedata[AEM_NOTEDATA_LEN + crypto_box_SEALBYTES];
	unsigned char ciphertext_empty[crypto_box_SEALBYTES];
	crypto_box_seal(ciphertext_notedata, zero, AEM_NOTEDATA_LEN, pk);
	crypto_box_seal(ciphertext_empty, (unsigned char*)"", 0, pk);

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

int setAccountLevel(const int64_t upk64, const int level) {
	if (level < 0 || level > 3) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return false;

	sqlite3_stmt *query;
	sqlite3_prepare_v2(db, "UPDATE userdata SET level=? WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_int(query, 1, level);
	sqlite3_bind_int64(query, 2, upk64);

	const int retval = (sqlite3_step(query) == SQLITE_DONE) ? 0 : -1;
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return retval;
}

int destroyAccount(const int64_t upk64) {
	sqlite3 *db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	int retval = 0;

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

	db = openDb(AEM_PATH_DB_MESSAGES, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_prepare_v2(db, "DELETE FROM msg WHERE upk64=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, upk64);
	if (sqlite3_step(query) != SQLITE_DONE) retval = -1;
	sqlite3_finalize(query);
	sqlite3_close_v2(db);

	return retval;
}
