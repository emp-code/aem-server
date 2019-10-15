#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <sodium.h>
#include <sqlite3.h>

#include "Message.h"

#include "Includes/CharToInt64.h"

#include "Database.h"

#define AEM_ADDRESS_ARGON2_OPSLIMIT 3
#define AEM_ADDRESS_ARGON2_MEMLIMIT 67108864

#define AEM_DB_BUSY_TIMEOUT 15000 // milliseconds

#define AEM_PATH_DB_MESSAGES "/Messages.aed"
#define AEM_PATH_DB_USERS  "/Users.aed"

__attribute__((warn_unused_result))
static sqlite3 *openDb(const char * const path, const int flags) {
	if (path == NULL) return NULL;

	sqlite3 *db;
	if (sqlite3_open_v2(path, &db, flags, NULL) != SQLITE_OK) {
		sqlite3_close_v2(db);
		return NULL;
	}

	sqlite3_exec(db, "PRAGMA temp_store=MEMORY", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA secure_delete=true", NULL, NULL, NULL);
	sqlite3_busy_timeout(db, AEM_DB_BUSY_TIMEOUT);

	return db;
}

__attribute__((warn_unused_result))
int64_t addressToHash(const unsigned char * const addr, const unsigned char * const addrKey) {
	if (addr == NULL || addrKey == NULL) return 0;

	unsigned char hash16[16];
	if (crypto_pwhash(hash16, 16, (char*)addr, 15, addrKey, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) return 0;
	return charToInt64(hash16);
}

__attribute__((warn_unused_result))
int64_t gkHash(const unsigned char * const in, const size_t len, const int64_t upk64, const unsigned char * const hashKey) {
	if (in == NULL || len < 1 || hashKey == NULL) return 0;

	unsigned char saltyKey[24];
	memcpy(saltyKey, &upk64, 8);
	memcpy(saltyKey + 8, hashKey, 16);

	unsigned char hash16[16];
	crypto_generichash(hash16, 16, in, len, saltyKey, 24);
//	if (crypto_pwhash(hash16, 16, (char*)in, len, saltyKey, 3 /*OpsLimit*/, 67108864 /*MemLimit*/, crypto_pwhash_ALG_ARGON2ID13) != 0) return 0;
	return charToInt64(hash16);
}

__attribute__((warn_unused_result))
bool upk64Exists(const int64_t upk64) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return false;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT 1 FROM userdata WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return false;}

	sqlite3_bind_int64(query, 1, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_ROW);
}

__attribute__((warn_unused_result))
int getPublicKeyFromAddress(const unsigned char * const addr, unsigned char * const pk, const unsigned char * const addrKey, unsigned char * const flags) {
	if (addr == NULL || pk == NULL || addrKey == NULL || flags == NULL) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT publickey, flags FROM address INNER JOIN userdata USING(upk64) WHERE hash=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_int64(query, 1, addressToHash(addr, addrKey));

	ret = sqlite3_step(query);
	if (ret != SQLITE_ROW || sqlite3_column_bytes(query, 0) != crypto_box_PUBLICKEYBYTES) {
		sqlite3_finalize(query);
		sqlite3_close_v2(db);
		return -1;
	}

	memcpy(pk, sqlite3_column_blob(query, 0), crypto_box_PUBLICKEYBYTES);

	const int intFlags = sqlite3_column_int(query, 1);
	*flags = (intFlags >= 0 && intFlags < 255) ? intFlags : 0;

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return 0;
}

__attribute__((warn_unused_result))
int getUserLevel(const int64_t upk64) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT level FROM userdata WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_int64(query, 1, upk64);
	if (sqlite3_step(query) != SQLITE_ROW) {sqlite3_finalize(query); sqlite3_close_v2(db); return -1;}

	const int level = sqlite3_column_int(query, 0);

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return level;
}

__attribute__((warn_unused_result))
int getUserInfo(const int64_t upk64, uint8_t * const level, unsigned char ** const noteData, unsigned char ** const addrData, uint16_t * const lenAddr, unsigned char ** const gkData, uint16_t * const lenGk, unsigned char * const limits) {
	if (upk64 == 0 || level == NULL || noteData == NULL || addrData == NULL || lenAddr == NULL || gkData == NULL || lenGk == NULL || limits == NULL) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT storage, addrnorm, addrshld FROM limits WHERE (storage BETWEEN 0 AND 255) AND (addrnorm BETWEEN 0 AND 255) AND (addrshld BETWEEN 0 AND 255)", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	for (int i = 0; i < 4; i++) {
		if (sqlite3_step(query) != SQLITE_ROW) {sqlite3_finalize(query); sqlite3_close_v2(db); return -1;}
		limits[(i * 3) + 0] = sqlite3_column_int(query, 0);
		limits[(i * 3) + 1] = sqlite3_column_int(query, 1);
		limits[(i * 3) + 2] = sqlite3_column_int(query, 2);
	}
	sqlite3_finalize(query);

	ret = sqlite3_prepare_v2(db, "SELECT level, notedata, addrdata, gkdata FROM userdata WHERE upk64=? AND notedata IS NOT NULL AND addrdata IS NOT NULL AND gkdata IS NOT NULL", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

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

__attribute__((warn_unused_result))
int getAdminData(unsigned char ** const adminData) {
	if (adminData == NULL) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READONLY);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT upk64, level, addrnorm, addrshld FROM userdata LIMIT 1024", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3 * const dbMsg = openDb(AEM_PATH_DB_MESSAGES, SQLITE_OPEN_READONLY);
	if (dbMsg == NULL) {sqlite3_close_v2(db); return -1;}

	*adminData = calloc(AEM_ADMINDATA_LEN, 1);

	int userCount = 0;
	while (sqlite3_step(query) == SQLITE_ROW) {
		const int64_t upk64 = sqlite3_column_int64(query, 0);
		memcpy(*adminData + (userCount * 11), &upk64, 8);

		int memberLevel = sqlite3_column_int(query, 1);
		if (memberLevel < 0 || memberLevel > 3) memberLevel = 0;

		int naddr = sqlite3_column_int(query, 2);
		int saddr = sqlite3_column_int(query, 3);
		if (naddr < 0 || naddr > 255) naddr = 0;
		if (saddr < 0 || saddr > 255) saddr = 0;

		int space = 0;
		sqlite3_stmt *queryMsg;
		ret = sqlite3_prepare_v2(dbMsg, "SELECT MIN(SUM(LENGTH(msg)) / 1024 / 1024, 255) FROM msg WHERE upk64=?", -1, &queryMsg, NULL);
		if (ret == SQLITE_OK) {
			sqlite3_bind_int64(queryMsg, 1, upk64);
			ret = sqlite3_step(queryMsg);
			space = (ret != SQLITE_ROW) ? 0 : sqlite3_column_int(queryMsg, 0);
			sqlite3_finalize(queryMsg);
		}

		const unsigned char memberInfo = memberLevel | (space << 2);
		*(*adminData + (userCount * 11) + 8) = memberInfo;

		*(*adminData + (userCount * 11) + 9) = naddr;
		*(*adminData + (userCount * 11) + 10) = saddr;

		userCount++;
	}

	sqlite3_close_v2(dbMsg);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return 0;
}

__attribute__((warn_unused_result))
unsigned char *getUserMessages(const int64_t upk64, uint8_t * const msgCount, const size_t maxSize) {
	if (msgCount == NULL || maxSize < 1) return NULL;

	sqlite3 * const db = openDb(AEM_PATH_DB_MESSAGES, SQLITE_OPEN_READONLY);
	if (db == NULL) return NULL;

	sqlite3_stmt *query;
	const int ret = sqlite3_prepare_v2(db, "SELECT msg, row_number FROM (SELECT rowid, row_number() OVER (ORDER BY rowid ASC) AS row_number FROM msg WHERE upk64=? ORDER BY rowid DESC) JOIN msg ON msg.rowid=rowid LIMIT 255", -1, &query, NULL);
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

		const int sizeFactor = ((msgLen - 2) / 1024) - 1; // 0 = 1KiB, 255 = 256KiB
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

__attribute__((warn_unused_result))
int addUserMessage(const int64_t upk64, const unsigned char * const msgData, const size_t msgLen) {
	if (msgData == NULL || msgLen < 1) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_MESSAGES, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO msg (upk64, msg) VALUES (?, ?)", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_int64(query, 1, upk64);
	sqlite3_bind_blob(query, 2, msgData, msgLen, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

__attribute__((warn_unused_result))
int deleteAddress(const int64_t upk64, const int64_t hash, const bool isShield, const unsigned char * const addrData, const size_t lenAddrData) {
	if (addrData == NULL || lenAddrData < 1) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	const char *sql = isShield
	? "DELETE FROM address WHERE hash = ? AND upk64 = ? AND flags & ?"
	: "DELETE FROM address WHERE hash = ? AND upk64 = ? AND NOT (flags & ?)";

	int ret = sqlite3_prepare_v2(db, sql, -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_int64(query, 1, hash);
	sqlite3_bind_int64(query, 2, upk64);
	sqlite3_bind_int(query, 3, AEM_FLAGS_ADDR_ISSHIELD);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	if (ret != SQLITE_DONE || sqlite3_changes(db) != 1) {sqlite3_close_v2(db); return -1;}

	sql = isShield
	? "UPDATE userdata SET addrdata = ?, addrshld = addrshld - 1 WHERE upk64 = ?"
	: "UPDATE userdata SET addrdata = ?, addrnorm = addrnorm - 1 WHERE upk64 = ?";

	ret = sqlite3_prepare_v2(db, sql, -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_blob(query, 1, addrData, lenAddrData, SQLITE_STATIC);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

__attribute__((warn_unused_result))
static bool isBlockedByGatekeeper_test(sqlite3 * const db, const int64_t upk64, const unsigned char * const hashKey, const unsigned char * const text, const size_t lenText) {
	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT 1 FROM gatekeeper WHERE hash=? AND upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_int64(query, 1, gkHash(text, lenText, upk64, hashKey));
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	return (ret == SQLITE_ROW);
}

__attribute__((warn_unused_result))
bool isBlockedByGatekeeper(const int16_t * const countryCode, const char *domain, const size_t lenDomain, const char* from, const size_t lenFrom, const int64_t upk64, const unsigned char * const hashKey) {
	if (domain == NULL || lenDomain < 1 || from == NULL || lenFrom < 1 || hashKey == NULL) false;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	const bool result = (
	   isBlockedByGatekeeper_test(db, upk64, hashKey, (unsigned char*)countryCode, 2)
	|| isBlockedByGatekeeper_test(db, upk64, hashKey, (unsigned char*)domain, lenDomain)
	|| isBlockedByGatekeeper_test(db, upk64, hashKey, (unsigned char*)from, lenFrom)
	);

	sqlite3_close_v2(db);
	return result;
}

// Format: item1\nitem2\n...
__attribute__((warn_unused_result))
int updateGatekeeper(const unsigned char * const ownerPk, char * const gkData, const size_t lenGkData, const unsigned char * const hashKey) {
	if (ownerPk == NULL || gkData == NULL || lenGkData < 1 || hashKey == NULL) return -1;

	if (gkData[lenGkData - 1] != '\n') return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "DELETE FROM gatekeeper WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	const int64_t upk64 = charToInt64(ownerPk);

	sqlite3_bind_int64(query, 1, upk64);
	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	if (ret != SQLITE_DONE) {sqlite3_close_v2(db); return -1;}

	const char *lf = gkData;
	while (lf != NULL) {
		char * const next = strchr(lf + 1, '\n');
		if (next == NULL) break;
		const size_t len = next - lf - (lf == gkData ? 0 : 1);
		if (*lf == '\n') lf++;

		ret = sqlite3_prepare_v2(db, "INSERT INTO gatekeeper (hash, upk64) VALUES (?, ?)", -1, &query, NULL);
		if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

		sqlite3_bind_int64(query, 1, gkHash((unsigned char*)lf, len, upk64, hashKey));
		sqlite3_bind_int64(query, 2, upk64);
		ret = sqlite3_step(query);
		sqlite3_finalize(query);
		if (ret != SQLITE_DONE) {sqlite3_close_v2(db); return -1;}

		lf = next;
		if (lenGkData - (next - gkData) < 2) break;
	}

	ret = sqlite3_prepare_v2(db, "UPDATE userdata SET gkdata=? WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	unsigned char * const ciphertext = malloc(lenGkData + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, (unsigned char*)gkData, lenGkData, ownerPk);

	sqlite3_bind_blob(query, 1, ciphertext, lenGkData + crypto_box_SEALBYTES, free);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

__attribute__((warn_unused_result))
int deleteMessages(const int64_t upk64, const uint8_t * const ids, const int count) {
	if (ids == NULL || count < 1) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_MESSAGES, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT rowid, row_number() OVER (ORDER BY rowid ASC) AS row_number FROM msg WHERE upk64=?", -1, &query, NULL);
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

	int retval = 0;
	for (int i = 0; i < rowCount; i++) {
		ret = sqlite3_prepare_v2(db, "DELETE FROM msg WHERE rowid=? AND upk64=?", -1, &query, NULL);
		if (ret == SQLITE_OK) {
			sqlite3_bind_int(query, 1, rowIds[i]);
			sqlite3_bind_int64(query, 2, upk64);
			ret = sqlite3_step(query);
			sqlite3_finalize(query);
			if (ret != SQLITE_DONE) retval = -1;
		}
	}

	sqlite3_close_v2(db);
	return retval;
}

__attribute__((warn_unused_result))
int updateNoteData(const int64_t upk64, const unsigned char * const noteData) {
	if (noteData == NULL) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "UPDATE userdata SET notedata=? WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_blob(query, 1, noteData, AEM_NOTEDATA_LEN + crypto_box_SEALBYTES, SQLITE_STATIC);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

__attribute__((warn_unused_result))
int updateAddress(const int64_t upk64, const unsigned char * const addrData, const size_t lenAddrData) {
	if (addrData == NULL || lenAddrData < 1) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "UPDATE userdata SET addrdata=? WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_blob(query, 1, addrData, lenAddrData, SQLITE_STATIC);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

__attribute__((warn_unused_result))
int updateAddressSettings(const int64_t upk64, const int64_t * const addrHash, const unsigned char * const addrFlags, const int addressCount) {
	if (addrHash == NULL || addrFlags == NULL || addressCount < 1) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	for (int i = 0; i < addressCount; i++) {
		sqlite3_stmt *query;
		int ret = sqlite3_prepare_v2(db, "UPDATE address SET flags = (? | (SELECT flags & ? FROM address WHERE hash=?)) WHERE hash=? AND upk64=?", -1, &query, NULL);
		if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

		sqlite3_bind_int(query, 1, addrFlags[i]);
		sqlite3_bind_int(query, 2, AEM_FLAGS_ADDR_ISSHIELD);
		sqlite3_bind_int64(query, 3, addrHash[i]);
		sqlite3_bind_int64(query, 4, addrHash[i]);
		sqlite3_bind_int64(query, 5, upk64);

		ret = sqlite3_step(query);
		if (ret != SQLITE_DONE) {sqlite3_close_v2(db); return -1;}
		sqlite3_finalize(query);
	}

	sqlite3_close_v2(db);
	return 0;
}

__attribute__((warn_unused_result))
static bool isUserAtAddressLimit(sqlite3 * const db, const uint64_t upk64, const bool isShield) {
	sqlite3_stmt *query;
	const char * const sql = isShield
	? "SELECT 1 WHERE (SELECT addrshld FROM LIMITS WHERE level = (SELECT level FROM userdata WHERE upk64=?)) <= (SELECT COUNT(1) FROM address WHERE upk64=? AND flags & ?)"
	: "SELECT 1 WHERE (SELECT addrnorm FROM LIMITS WHERE level = (SELECT level FROM userdata WHERE upk64=?)) <= (SELECT COUNT(1) FROM address WHERE upk64=? AND NOT (flags & ?))";

	int ret = sqlite3_prepare_v2(db, sql, -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_int64(query, 1, upk64);
	sqlite3_bind_int64(query, 2, upk64);
	sqlite3_bind_int(query, 3, AEM_FLAGS_ADDR_ISSHIELD);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	return (ret == SQLITE_ROW);
}

static int updateUserAddressCount(sqlite3 * const db, const uint64_t upk64, const bool isShield) {
	sqlite3_stmt *query;
	const char * const sql = isShield
	? "UPDATE userdata SET addrshld = (SELECT COUNT(1) FROM address WHERE upk64=? AND flags & ?) WHERE upk64=?"
	: "UPDATE userdata SET addrnorm = (SELECT COUNT(1) FROM address WHERE upk64=? AND NOT (flags & ?)) WHERE upk64=?";

	int ret = sqlite3_prepare_v2(db, sql, -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_int64(query, 1, upk64);
	sqlite3_bind_int(query, 2, AEM_FLAGS_ADDR_ISSHIELD);
	sqlite3_bind_int64(query, 3, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);

	return ret;
}

__attribute__((warn_unused_result))
int addAddress(const int64_t upk64, const int64_t hash, const bool isShield) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	if (isUserAtAddressLimit(db, upk64, isShield)) {
		sqlite3_close_v2(db);
		return -1;
	}

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO address (hash, upk64, flags) VALUES (?, ?, ?)", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	const int flags = isShield ? AEM_FLAGS_ADDR_ISSHIELD | AEM_FLAGS_ADDR_USE_GK : AEM_FLAGS_ADDR_USE_GK;
	sqlite3_bind_int64(query, 1, hash);
	sqlite3_bind_int64(query, 2, upk64);
	sqlite3_bind_int(query, 3, flags);

	ret = sqlite3_step(query);
	if (ret == SQLITE_DONE) {
		updateUserAddressCount(db, upk64, isShield);
	}

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

__attribute__((warn_unused_result))
int addAccount(const unsigned char * const pk) {
	if (pk == NULL) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	unsigned char zero[AEM_NOTEDATA_LEN];
	sodium_memzero(zero, AEM_NOTEDATA_LEN);

	unsigned char ciphertext_notedata[AEM_NOTEDATA_LEN + crypto_box_SEALBYTES];
	unsigned char ciphertext_empty[crypto_box_SEALBYTES];
	crypto_box_seal(ciphertext_notedata, zero, AEM_NOTEDATA_LEN, pk);
	crypto_box_seal(ciphertext_empty, (unsigned char*)"", 0, pk);

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO userdata (upk64, publickey, level, notedata, addrdata, gkdata, addrnorm, addrshld) VALUES (?,?,0,?,?,?,0,0)", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	int64_t upk64;
	memcpy(&upk64, pk, 8);

	sqlite3_bind_int64(query, 1, upk64);
	sqlite3_bind_blob(query, 2, pk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);
	sqlite3_bind_blob(query, 3, ciphertext_notedata, AEM_NOTEDATA_LEN + crypto_box_SEALBYTES, SQLITE_STATIC);
	sqlite3_bind_blob(query, 4, ciphertext_empty, crypto_box_SEALBYTES, SQLITE_STATIC);
	sqlite3_bind_blob(query, 5, ciphertext_empty, crypto_box_SEALBYTES, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

__attribute__((warn_unused_result))
int setAccountLevel(const int64_t upk64, const int level) {
	if (level < 0 || level > 3) return -1;

	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return false;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "UPDATE userdata SET level=? WHERE upk64=?", -1, &query, NULL);
	if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

	sqlite3_bind_int(query, 1, level);
	sqlite3_bind_int64(query, 2, upk64);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

__attribute__((warn_unused_result))
int destroyAccount(const int64_t upk64) {
	sqlite3 *db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	int retval = 0;

	sqlite3_stmt *query;

	int ret = sqlite3_prepare_v2(db, "DELETE FROM userdata WHERE upk64=?", -1, &query, NULL);
	if (ret == SQLITE_OK) {
		sqlite3_bind_int64(query, 1, upk64);
		if (sqlite3_step(query) != SQLITE_DONE) retval = -1;
		sqlite3_finalize(query);
	} else retval = -1;

	ret = sqlite3_prepare_v2(db, "DELETE FROM address WHERE upk64=?", -1, &query, NULL);
	if (ret == SQLITE_OK) {
		sqlite3_bind_int64(query, 1, upk64);
		if (sqlite3_step(query) != SQLITE_DONE) retval = -1;
		sqlite3_finalize(query);
	} else retval = -1;

	ret = sqlite3_prepare_v2(db, "DELETE FROM gatekeeper WHERE upk64=?", -1, &query, NULL);
	if (ret == SQLITE_OK) {
		sqlite3_bind_int64(query, 1, upk64);
		if (sqlite3_step(query) != SQLITE_DONE) retval = -1;
		sqlite3_finalize(query);
	} else retval = -1;

	sqlite3_close_v2(db);

	db = openDb(AEM_PATH_DB_MESSAGES, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	ret = sqlite3_prepare_v2(db, "DELETE FROM msg WHERE upk64=?", -1, &query, NULL);
	if (ret == SQLITE_OK) {
		sqlite3_bind_int64(query, 1, upk64);
		if (sqlite3_step(query) != SQLITE_DONE) retval = -1;
	} else retval = -1;

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return retval;
}

__attribute__((warn_unused_result))
int updateLimits(const int * const maxStorage, const int * const maxAddrNrm, const int * const maxAddrShd) {
	sqlite3 * const db = openDb(AEM_PATH_DB_USERS, SQLITE_OPEN_READWRITE);
	if (db == NULL) return -1;

	int ret;
	for (int i = 0; i < 4; i++) {
		sqlite3_stmt *query;
		ret = sqlite3_prepare_v2(db, "UPDATE limits SET storage=?, addrnorm=?, addrshld=? WHERE level=?", -1, &query, NULL);
		if (ret != SQLITE_OK) {sqlite3_close_v2(db); return -1;}

		sqlite3_bind_int(query, 1, maxStorage[i]);
		sqlite3_bind_int(query, 2, maxAddrNrm[i]);
		sqlite3_bind_int(query, 3, maxAddrShd[i]);
		sqlite3_bind_int(query, 4, i);

		ret = sqlite3_step(query);
		if (ret != SQLITE_DONE) break;
		sqlite3_finalize(query);
	}

	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}
