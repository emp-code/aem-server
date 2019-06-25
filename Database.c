#include <stdint.h>
#include <string.h>

#include <sodium.h>
#include <sqlite3.h>

#include "IntMsg.h"

#include "Database.h"

#define AEM_PATH_DB_MESSAGES "Data/Messages.aed"
#define AEM_PATH_DB_USERS  "Data/Users.aed"

// A slower hashing method here would increase security at the cost of additional strain on the server.
// Collisions here cause additional, unintended "aliases" for addresses. That isn't necessarily bad.
int64_t addressToHash(const unsigned char addr[18], const unsigned char hashKey[16]) {
	unsigned char hash16[16];
	crypto_generichash(hash16, 16, addr, 18, hashKey, 16);

	int64_t result;
	memcpy(&result, hash16, 8);
	return result;
}

int getPublicKeyFromAddress(const unsigned char addr[18], unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char hashKey[16], int *memberLevel) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT ownerpk,level FROM address JOIN users ON publickey=ownerpk WHERE hash=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, addressToHash(addr, hashKey));

	ret = sqlite3_step(query);
	if (ret != SQLITE_ROW || sqlite3_column_bytes(query, 0) != crypto_box_PUBLICKEYBYTES) {sqlite3_finalize(query); sqlite3_close_v2(db); return -1;}

	memcpy(pk, sqlite3_column_blob(query, 0), crypto_box_PUBLICKEYBYTES);
	*memberLevel = sqlite3_column_int(query, 1);

	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return 0;
}

int getUserInfo(const unsigned char pk[crypto_box_PUBLICKEYBYTES], uint8_t * const level, unsigned char ** const noteData, unsigned char ** const addrData, uint16_t * const lenAddr, unsigned char ** const gkData, uint16_t * const lenGk) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT level, notedata, addrdata, gkdata FROM userdata WHERE publickey=?", -1, &query, NULL);
	if (ret != SQLITE_OK) return -1;

	sqlite3_bind_blob(query, 1, pk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);
	if (sqlite3_step(query) != SQLITE_ROW) {sqlite3_finalize(query); sqlite3_close_v2(db); return -1;}

	*level = sqlite3_column_int(query, 0);

	*noteData = calloc(AEM_NOTEDATA_LEN + crypto_box_SEALBYTES, 1);
	if (*noteData == NULL) {sqlite3_finalize(query); sqlite3_close(db); return -1;}
	memcpy(*noteData, sqlite3_column_blob(query, 1), AEM_NOTEDATA_LEN + crypto_box_SEALBYTES);

	*lenAddr = sqlite3_column_bytes(query, 2);
	*addrData = malloc(*lenAddr);
	if (*addrData == NULL) {sqlite3_finalize(query); sqlite3_close(db); free(noteData); return -1;}
	memcpy(*addrData, sqlite3_column_blob(query, 2), *lenAddr);

	*lenGk = sqlite3_column_bytes(query, 3);
	*gkData = malloc(*lenGk);
	if (*gkData == NULL) {sqlite3_finalize(query); sqlite3_close(db); free(noteData); free(*addrData); return -1;}
	memcpy(*gkData, sqlite3_column_blob(query, 3), *lenGk);

	sqlite3_finalize(query);
	sqlite3_close(db);
	return 0;
}

unsigned char *getUserMessages(const unsigned char pk[crypto_box_PUBLICKEYBYTES], uint8_t * const msgCount, const size_t maxSize) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_MESSAGES, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return NULL;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "SELECT msg FROM messages WHERE ownerpk=? ORDER BY rowid DESC", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, pk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);

	unsigned char* data = calloc(maxSize, 1);
	size_t totalSize = 0;
	*msgCount = 0;

	while (sqlite3_step(query) == SQLITE_ROW && *msgCount < 256) {
		const size_t sz = sqlite3_column_bytes(query, 0);
		if (sz < 5) {sqlite3_finalize(query); sqlite3_close_v2(db); return NULL;}

		if (totalSize + sz > maxSize) break;

		const size_t msgLen = sz - AEM_INTMSG_HEADERSIZE - (crypto_box_SEALBYTES * 2); // Length of decrypted Body part
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

int addUserMessage(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const unsigned char *msgData, const size_t msgLen) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_MESSAGES, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO messages (ownerpk, msg) VALUES (?, ?)", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, ownerPk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);
	sqlite3_bind_blob(query, 2, msgData, msgLen, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int deleteAddress(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const int64_t hash, const unsigned char *addrData, const size_t lenAddrData) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "DELETE FROM address WHERE hash=? AND ownerpk=?", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, hash);
	sqlite3_bind_blob(query, 2, ownerPk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	if (ret != SQLITE_DONE) {sqlite3_close_v2(db); return -1;}

	ret = sqlite3_prepare_v2(db, "UPDATE users SET addrdata=? WHERE publickey=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, addrData, lenAddrData, SQLITE_STATIC);
	sqlite3_bind_blob(query, 2, ownerPk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);

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

		unsigned char hash[64];
		crypto_generichash(hash, 64, (unsigned char*)lf, len, hashKey, 16);

		sqlite3_prepare_v2(db, "INSERT INTO gatekeeper VALUES (?, ?)", -1, &query, NULL);
		sqlite3_bind_int64(query, 1, upk64);
		sqlite3_bind_blob(query, 2, hash, 64, SQLITE_STATIC);
		sqlite3_step(query);
		sqlite3_finalize(query);

		lf = next;
		if (lenGkData - (next - gkData) < 2) break;
	}

	unsigned char *ciphertext = malloc(lenGkData + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, (unsigned char*)gkData, lenGkData, ownerPk);

	sqlite3_prepare_v2(db, "UPDATE users SET gkdata=? WHERE publickey=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, ciphertext, lenGkData + crypto_box_SEALBYTES, free);
	sqlite3_bind_blob(query, 2, ownerPk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);
	sqlite3_step(query);
	sqlite3_finalize(query);

	sqlite3_close_v2(db);
	return 0;
}

int updateNoteData(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const unsigned char *noteData) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "UPDATE userdata SET notedata=? WHERE publickey=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, noteData, AEM_NOTEDATA_LEN + crypto_box_SEALBYTES, SQLITE_STATIC);
	sqlite3_bind_blob(query, 2, ownerPk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int updateAddress(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const unsigned char *addrData, const size_t lenAddrData) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "UPDATE users SET addrdata=? WHERE publickey=?", -1, &query, NULL);
	sqlite3_bind_blob(query, 1, addrData, lenAddrData, SQLITE_STATIC);
	sqlite3_bind_blob(query, 2, ownerPk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}

int addAddress(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const int64_t hash) {
	sqlite3 *db;
	if (sqlite3_open_v2(AEM_PATH_DB_USERS, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) return -1;

	sqlite3_stmt *query;
	int ret = sqlite3_prepare_v2(db, "INSERT INTO address (hash, ownerpk) VALUES (?, ?)", -1, &query, NULL);
	sqlite3_bind_int64(query, 1, hash);
	sqlite3_bind_blob(query, 2, ownerPk, crypto_box_PUBLICKEYBYTES, SQLITE_STATIC);

	ret = sqlite3_step(query);
	sqlite3_finalize(query);
	sqlite3_close_v2(db);
	return (ret == SQLITE_DONE) ? 0 : -1;
}
