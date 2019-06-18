#include <stdint.h>
#include <string.h>

#include <sodium.h>
#include <sqlite3.h>

#include "Database.h"

#define AEM_PATH_DB_MESSAGES "Data/Messages.aed"
#define AEM_PATH_DB_USERS  "Data/Users.aed"

#define AEM_MSG_HEADSIZE 37

// A slower hashing method here would increase security at the cost of additional strain on the server.
// Collisions here cause additional, unintended "aliases" for addresses. That isn't necessarily bad.
static int64_t addressToHash(const unsigned char addr[16], const unsigned char hashKey[16]) {
	unsigned char hash16[16];
	crypto_generichash(hash16, 16, addr, 16, hashKey, 16);

	int64_t result;
	memcpy(&result, hash16, 8);
	return result;
}

int getPublicKeyFromAddress(const unsigned char addr[16], unsigned char pk[32], const unsigned char hashKey[16], int *memberLevel) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT ownerpk,level FROM address JOIN users ON publickey=ownerpk WHERE hash=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, addressToHash(addr, hashKey));

	ret = sqlite3_step(query);
	if (ret != SQLITE_ROW || sqlite3_column_bytes(query, 0) != 32) {
		sqlite3_finalize(query);
		sqlite3_close_v2(db);
		return -1;
	}

	memcpy(pk, sqlite3_column_blob(query, 0), 32);
	*memberLevel = sqlite3_column_int(query, 1);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return 0;
}

unsigned char *getUserAddresses(const unsigned char pk[32], uint16_t *addrDataSize) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return NULL;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT addrdata FROM users WHERE publickey=?", -1, &query, NULL);
	if (ret != SQLITE_OK) return NULL;

	sqlite3_bind_blob(query, 1, pk, 32, SQLITE_STATIC);
	if (sqlite3_step(query) != SQLITE_ROW) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

	*addrDataSize = sqlite3_column_bytes(query, 0);
	unsigned char* data = malloc(*addrDataSize);
	if (data == NULL) return NULL;
	memcpy(data, sqlite3_column_blob(query, 0), *addrDataSize);

	sqlite3_finalize(query);
	sqlite3_close(db);
	return data;
}

unsigned char *getUserMessages(const unsigned char pk[32], int *msgCount, const size_t maxSize) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_MESSAGES, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return NULL;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT msg FROM messages WHERE ownerpk=? ORDER BY rowid DESC", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, pk, 32, SQLITE_STATIC);

	unsigned char* data = calloc(maxSize, 1);
	size_t totalSize = 0;
	*msgCount = 0;

	while (sqlite3_step(query) == SQLITE_ROW) {
		const size_t sz = sqlite3_column_bytes(query, 0);
		if (sz < 5) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

		if (totalSize + sz > maxSize) break;

		const size_t msgLen = sz - AEM_MSG_HEADSIZE - (crypto_box_SEALBYTES * 2); // Length of decrypted Body part
		if ((msgLen - 2) % 1024 != 0) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

		int sizeFactor = ((msgLen - 2) / 1024) - 1; // 0 = 1KiB, 255=256KiB
		if (sizeFactor > 255) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

		data[totalSize] = sizeFactor;
		memcpy(data + totalSize + 1, sqlite3_column_blob(query, 0), sz);
		totalSize += sz + 1;
		(*msgCount)++;
	}

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return data;
}

int addUserMessage(const unsigned char ownerPk[32], const unsigned char *msgData, const size_t msgLen) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_MESSAGES, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO messages (ownerpk, msg) VALUES (?, ?)", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, ownerPk, 32, SQLITE_STATIC);
	sqlite3_bind_blob(query, 2, msgData, msgLen, SQLITE_STATIC);

	ret = sqlite3_step(query);
	const int retval = (ret == SQLITE_DONE) ? 0 : -1;

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return retval;
}
