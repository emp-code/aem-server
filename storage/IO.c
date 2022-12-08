#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/aes.h"
#include "../Common/memeq.h"

#include "IO.h"

#define AEM_STINDEX_PAD 90000 // 36B * 2500

static unsigned char stindexKey[AEM_LEN_KEY_STI];
static unsigned char storageKey[AEM_LEN_KEY_STO];

struct aem_stindex {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	uint16_t msgCount;
	uint8_t level;
	uint16_t *msg;
};

static unsigned char limits[] = {0,0,0,0}; // 0-255 MiB

static struct aem_stindex *stindex;
static uint16_t stindexCount;

static size_t getUserStorageAmount(const int num) {
	size_t total = 0;
	for (int i = 0; i < stindex[num].msgCount; i++) {
		total += stindex[num].msg[i] * 16;
	}
	return total;
}

int32_t acc_storage_amount(unsigned char ** const res) {
	const int32_t resSize = stindexCount * (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t));
	*res = malloc(resSize);
	if (*res == NULL) {syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}

	for (int i = 0; i < stindexCount; i++) {
		const uint32_t bytes = getUserStorageAmount(i);
		memcpy(*res + i * (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t)), (unsigned char*)&bytes, sizeof(uint32_t));
		memcpy(*res + i * (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t)) + sizeof(uint32_t), stindex[i].pubkey, crypto_box_PUBLICKEYBYTES);
	}

	return resSize;
}

// Recreate the Stindex with levels, reordered to be in sync with the received list
int32_t acc_storage_levels(const unsigned char * const data, const size_t lenData) {
	if (lenData % (crypto_box_PUBLICKEYBYTES + 1) != 0) {syslog(LOG_ERR, "updateLevels(): Invalid format"); return AEM_INTCOM_RESPONSE_ERR;}

	const int recCount = lenData / (crypto_box_PUBLICKEYBYTES + 1);
	struct aem_stindex *newStindex = malloc(sizeof(struct aem_stindex) * recCount);
	if (newStindex == NULL) {syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}

	for (int i = 0; i < recCount; i++) {
		const size_t s = sizeof(struct aem_stindex);

		if (memeq(data + (i * (crypto_box_PUBLICKEYBYTES + 1)) + 1, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES)) { // In sync
			memcpy((unsigned char*)newStindex + i * s, (unsigned char*)stindex + i * s, s);
		} else { // Out of sync
			syslog(LOG_WARNING, "updateLevels: Out of sync");

			// Determine which, if any, Stindex record matches received account
			bool found = false;

			for (int j = 0; j < stindexCount; j++) {
				if (memeq(data + (i * (crypto_box_PUBLICKEYBYTES + 1)) + 1, stindex[j].pubkey, crypto_box_PUBLICKEYBYTES)) { // Match
					memcpy((unsigned char*)newStindex + i * s, (unsigned char*)stindex + j * s, s);
					found = true;
					break;
				}
			}

			if (!found) {
				memcpy(newStindex[i].pubkey, data + (i * (crypto_box_PUBLICKEYBYTES + 1)) + 1, crypto_box_PUBLICKEYBYTES);
				newStindex[i].msgCount = 0;
				newStindex[i].msg = NULL;
			}
		}

		newStindex[i].level = data[i * (crypto_box_PUBLICKEYBYTES + 1)];
	}

	free(stindex);
	stindex = newStindex;
	stindexCount = recCount;
	return AEM_INTCOM_RESPONSE_OK;
}

int32_t acc_storage_limits(const unsigned char * const new, const size_t lenNew) {
	if (lenNew != 4) return AEM_INTCOM_RESPONSE_ERR;
	memcpy(limits, new, lenNew);
	return AEM_INTCOM_RESPONSE_OK;
}

static void getStorageKey(unsigned char * const target, const unsigned char * const upk, const uint16_t sze) {
	uint64_t keyId;
	memcpy(&keyId, &sze, 2);
	memcpy((unsigned char*)&keyId + 2, upk, 6);

	// Uses random key for 'Trash'; the extra kdf/random is to resist timing attacks
	unsigned char empty[crypto_box_PUBLICKEYBYTES];
	memset(empty, 0xFF, crypto_box_PUBLICKEYBYTES);
	if (memeq(empty, upk, crypto_box_PUBLICKEYBYTES)) {
		crypto_kdf_derive_from_key(target, 32, keyId, "AEM-Sto0", storageKey);
		randombytes_buf(target, 32);
	} else {
		crypto_kdf_derive_from_key(target, 32, keyId, "AEM-Sto0", storageKey);
		randombytes_buf(empty, crypto_box_PUBLICKEYBYTES);
	}
}

static int saveStindex(void) {
	if (stindexCount < 1) return -1;

	size_t lenClear = 2;
	for (int i = 0; i < stindexCount; i++) {
		lenClear += (crypto_box_PUBLICKEYBYTES + 2 + (2 * stindex[i].msgCount));
	}

	const size_t lenPad = (lenClear % AEM_STINDEX_PAD == 0) ? 0 : AEM_STINDEX_PAD - (lenClear % AEM_STINDEX_PAD);

	unsigned char * const clear = malloc(lenClear + lenPad);
	if (clear == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}
	bzero(clear + lenClear, lenPad);

	memcpy(clear, &stindexCount, 2);
	size_t skip = 2;

	for (int i = 0; i < stindexCount; i++) {
		memcpy(clear + skip, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES);
		skip += crypto_box_PUBLICKEYBYTES;

		memcpy(clear + skip, &(stindex[i].msgCount), 2);
		skip += 2;

		memcpy(clear + skip, stindex[i].msg, 2 * stindex[i].msgCount);
		skip += (2 * stindex[i].msgCount);
	}

	const ssize_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear + lenPad;
	unsigned char * const encrypted = malloc(lenEncrypted);
	if (encrypted == NULL) {syslog(LOG_ERR, "Failed allocation"); free(clear); return -1;}

	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear + lenPad, encrypted, stindexKey);

	sodium_memzero(clear, lenClear);
	free(clear);

	const int fd = open("Stindex.aem", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {free(encrypted); return -1;}
	const ssize_t ret = write(fd, encrypted, lenEncrypted);
	close(fd);
	free(encrypted);

	return (ret == lenEncrypted) ? 0 : -1;
}

static bool idMatch(const int fdMsg, const int stindexNum, const int sze, const int pos, const unsigned char * const id) {
	unsigned char buf[16];
	if (pread(fdMsg, buf, 16, pos) != 16) {
		syslog(LOG_ERR, "Failed read");
		return false;
	}

	unsigned char aesKey[32];
	getStorageKey(aesKey, stindex[stindexNum].pubkey, sze);
	struct AES_ctx aes;
	AES_init_ctx(&aes, aesKey);
	sodium_memzero(aesKey, 32);

	AES_ECB_decrypt(&aes, buf);

	sodium_memzero(&aes, sizeof(struct AES_ctx));

	for (int j = 0; j < 16; j++) {
		if (id[j] != buf[j]) return false;
	}

	return true;
}

// Encrypts pubkey to obscure file-owner connection
static void getMsgPath(char path[77], const unsigned char upk[crypto_box_PUBLICKEYBYTES]) {
	unsigned char aesKey[32];
	struct AES_ctx aes;

	crypto_kdf_derive_from_key(aesKey, 32, 1, "AEM-Stp0", storageKey);
	AES_init_ctx(&aes, aesKey);
	sodium_memzero(aesKey, 32);

	unsigned char pkEnc[32];
	memcpy(pkEnc, upk, 32);
	AES_ECB_encrypt(&aes, pkEnc);
	AES_ECB_encrypt(&aes, pkEnc + 16);

	sodium_memzero(&aes, sizeof(struct AES_ctx));

	sodium_bin2hex(path + 12, 65, pkEnc, 32);

	unsigned char empty[crypto_box_PUBLICKEYBYTES];
	memset(empty, 0xFF, crypto_box_PUBLICKEYBYTES);

	if (memeq(empty, upk, crypto_box_PUBLICKEYBYTES)) {
		strcpy(path, "MessageData/Trash");
	} else {
		memcpy(path, "MessageData/", 12);
	}
}

// Public functions

int32_t api_internal_erase(const unsigned char * const upk, const size_t lenUpk) {
	if (lenUpk != crypto_box_PUBLICKEYBYTES) {syslog(LOG_ERR, "Erase: Invalid UPK length"); return AEM_INTCOM_RESPONSE_ERR;}

	char path[77];
	getMsgPath(path, upk);
	if (unlink(path) != 0 && errno != ENOENT) {syslog(LOG_ERR, "Erase: %m"); return AEM_INTCOM_RESPONSE_ERR;} // Treat file not existing (no message data to delete) as success

	int delNum = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memeq(stindex[i].pubkey, upk, crypto_box_PUBLICKEYBYTES)) {
			delNum = i;
			break;
		}
	}

	if (delNum != -1) {
		if (delNum < (stindexCount - 1)) {
			const size_t s = sizeof(struct aem_stindex);
			memmove((unsigned char*)stindex + s * delNum, (unsigned char*)stindex + s * (delNum + 1), s * (stindexCount - delNum - 1));
		}

		stindexCount--;
		saveStindex();
	}

	return AEM_INTCOM_RESPONSE_OK;
}

static void browse_infoBytes(unsigned char * const target, const int stindexNum) {
	uint32_t blocks = 0;
	for (int i = 0; i < stindex[stindexNum].msgCount; i++) {
		blocks += stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS;
	}

	const uint16_t count = stindex[stindexNum].msgCount;
	memcpy(target, &count, 2);
	memcpy(target + 2, &blocks, 4);
}

int32_t api_message_browse(const unsigned char * const req, const size_t lenReq, unsigned char ** const out) {
	const unsigned char * const upk = req;
	const unsigned char * const matchId = (lenReq == crypto_box_PUBLICKEYBYTES + 17) ? req + crypto_box_PUBLICKEYBYTES : NULL;
	if (matchId == NULL && lenReq != crypto_box_PUBLICKEYBYTES) return AEM_INTCOM_RESPONSE_ERR;

	int stindexNum = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memeq(stindex[i].pubkey, upk, crypto_box_PUBLICKEYBYTES)) {
			stindexNum = i;
			break;
		}
	}
	if (stindexNum < 0) return 0; // Stindex for account doesn't exist (new account, no messages received yet)

	*out = malloc(AEM_MAXLEN_MSGDATA);
	if (*out == NULL) {syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}
//	bzero(*msgData, AEM_MAXLEN_MSGDATA);
	browse_infoBytes(*out, stindexNum);

	char path[77];
	getMsgPath(path, stindex[stindexNum].pubkey);
	const int fdMsg = open(path, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fdMsg < 0) return AEM_INTCOM_RESPONSE_ERR;

	off_t filePos = lseek(fdMsg, 0, SEEK_END);

	int startIndex = stindex[stindexNum].msgCount - 1;
	int stopIndex = -1;

	if (matchId != NULL) {
		if (matchId[0] & AEM_FLAG_NEWER) {
			for (int i = stindex[stindexNum].msgCount - 1; i >= 0; i--) {
				filePos -= (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;

				if (idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, matchId + 1)) {
					stopIndex = i;
					break;
				}
			}

			if (stopIndex == -1) {close(fdMsg); return AEM_INTCOM_RESPONSE_NOTEXIST;} // matchId not found
			filePos = lseek(fdMsg, 0, SEEK_END);
		} else { // older
			startIndex = 0;

			const off_t startFilePos = (stindex[stindexNum].msg[0] + AEM_MSG_MINBLOCKS) * 16;
			filePos = lseek(fdMsg, startFilePos, SEEK_SET);
			if (filePos != startFilePos) {close(fdMsg); return AEM_INTCOM_RESPONSE_ERR;}

			for (int i = 1; i < stindex[stindexNum].msgCount; i++) {
				if (idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, matchId + 1)) {
					startIndex = i - 1;
					break;
				}

				filePos += (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;
			}

			if (startIndex == 0) {close(fdMsg); return AEM_INTCOM_RESPONSE_NOTEXIST;} // matchId not found, or is the oldest
		}
	}

	int offset = 6; // browse_infoBytes

	for (int i = startIndex; i > stopIndex; i--) {
		const uint16_t sze = stindex[stindexNum].msg[i];
		if (offset + 2 + ((sze + AEM_MSG_MINBLOCKS) * 16) > AEM_MAXLEN_MSGDATA) break;

		memcpy(*out + offset, &sze, 2);
		offset += 2;

		filePos -= (sze + AEM_MSG_MINBLOCKS) * 16;
		if (pread(fdMsg, *out + offset, (sze + AEM_MSG_MINBLOCKS) * 16, filePos) != (sze + AEM_MSG_MINBLOCKS) * 16) {
			syslog(LOG_ERR, "Failed read (%d)", sze);
			break;
		}

		unsigned char aesKey[32];
		getStorageKey(aesKey, stindex[stindexNum].pubkey, stindex[stindexNum].msg[i]);
		struct AES_ctx aes;
		AES_init_ctx(&aes, aesKey);
		sodium_memzero(aesKey, 32);

		for (int j = 0; j < (sze + AEM_MSG_MINBLOCKS); j++)
			AES_ECB_decrypt(&aes, *out + offset + (j * 16));

		sodium_memzero(&aes, sizeof(struct AES_ctx));

		offset += (sze + AEM_MSG_MINBLOCKS) * 16;
	}

	close(fdMsg);
	return offset;
}

int32_t api_message_delete(const unsigned char req[crypto_box_PUBLICKEYBYTES], const size_t lenReq) {
	if (lenReq != crypto_box_PUBLICKEYBYTES + 1 && lenReq != crypto_box_PUBLICKEYBYTES + 16) return AEM_INTCOM_RESPONSE_ERR;

	const unsigned char * const upk = req;
	const unsigned char * const id = req + crypto_box_PUBLICKEYBYTES;

	int stindexNum = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memeq(upk, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES)) {
			stindexNum = i;
			break;
		}
	}

	if (stindexNum == -1) {syslog(LOG_NOTICE, "Invalid pubkey in delete request"); return AEM_INTCOM_RESPONSE_ERR;}

	char path[77];
	getMsgPath(path, stindex[stindexNum].pubkey);

	if (lenReq == crypto_box_PUBLICKEYBYTES + 1) { // Delete all
		const int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
		if (fd < 0) {syslog(LOG_ERR, "Erase: %m"); return AEM_INTCOM_RESPONSE_ERR;}
		close(fd);

		uint16_t * const newMsg = realloc(stindex[stindexNum].msg, 2);
		if (newMsg != NULL) stindex[stindexNum].msg = newMsg;
		stindex[stindexNum].msgCount = 0;
		saveStindex();

		return AEM_INTCOM_RESPONSE_OK;
	}

	const int fdMsg = open(path, O_RDWR | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fdMsg < 0) return AEM_INTCOM_RESPONSE_ERR;

	off_t filePos = lseek(fdMsg, 0, SEEK_END);
	const off_t fileSize = filePos;
	bool doneDelete = false;

	for (int i = stindex[stindexNum].msgCount - 1; i >= 1; i--) {
		filePos -= (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;

		if (!idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, id)) continue;
		doneDelete = true;

		// ID matches
		if (i < stindex[stindexNum].msgCount - 1) {
			// Messages to preserve after this one
			const off_t readPos = filePos + (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;

			const ssize_t readAmount = fileSize - readPos;
			unsigned char * const buf = malloc(readAmount);
			if (buf == NULL) {close(fdMsg); return AEM_INTCOM_RESPONSE_ERR;}

			const ssize_t readBytes = pread(fdMsg, buf, readAmount, readPos);
			if (readBytes != readAmount) {
				close(fdMsg);
				free(buf);
				syslog(LOG_ERR, "storage_delete: Failed read()");
				return AEM_INTCOM_RESPONSE_ERR;
			}

			const ssize_t writtenBytes = pwrite(fdMsg, buf, readAmount, filePos);
			free(buf);
			if (writtenBytes != readAmount) {
				close(fdMsg);
				syslog(LOG_ERR, "storage_delete: Failed write()");
				return AEM_INTCOM_RESPONSE_ERR;
			}
		}

		ftruncate(fdMsg, fileSize - ((stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16));

		if (i < stindex[stindexNum].msgCount - 1) {
			memmove((unsigned char*)stindex[stindexNum].msg + 2 * i, (unsigned char*)stindex[stindexNum].msg + 2 * (i + 1), 2 * (stindex[stindexNum].msgCount - i - 1));
		}

		stindex[stindexNum].msgCount--;
		saveStindex();
		break;
	}

	close(fdMsg);
	return doneDelete ? AEM_INTCOM_RESPONSE_OK : AEM_INTCOM_RESPONSE_ERR;
}

int32_t storage_write(unsigned char * const req, const size_t lenReq) {
	if (lenReq < crypto_box_PUBLICKEYBYTES || ((lenReq - crypto_box_PUBLICKEYBYTES) % 16) != 0) return AEM_INTCOM_RESPONSE_ERR;

	const ssize_t sze = ((lenReq - crypto_box_PUBLICKEYBYTES) / 16) - AEM_MSG_MINBLOCKS;
	if (sze < 0) return AEM_INTCOM_RESPONSE_ERR;
	unsigned char * const msg = req + crypto_box_PUBLICKEYBYTES;

	// Stindex
	const unsigned char * const upk = req;

	unsigned char empty[crypto_box_PUBLICKEYBYTES];
	memset(empty, 0xFF, crypto_box_PUBLICKEYBYTES);
	const bool isTrash = memeq(empty, upk, crypto_box_PUBLICKEYBYTES);

	int num = -1;
	if (!isTrash) {
		for (int i = 0; i < stindexCount; i++) {
			if (memeq(upk, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES)) {
				num = i;
				break;
			}
		}

		if (num != -1 && (int)getUserStorageAmount(num) >= (limits[stindex[num].level & 3]) * 1048576) return AEM_INTCOM_RESPONSE_LIMIT; // Over storage limit
	}

	char path[77];
	getMsgPath(path, upk);
	const int fdMsg = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW | (isTrash? O_TRUNC : O_APPEND), S_IRUSR | S_IWUSR | S_ISVTX);
	if (fdMsg < 0) {syslog(LOG_ERR, "storage_write(): Failed open: %m"); return AEM_INTCOM_RESPONSE_ERR;}

	const off_t oldFilesize = lseek(fdMsg, 0, SEEK_END);
	if (oldFilesize < 0) {syslog(LOG_ERR, "storage_write(): Failed lseek: %m"); return AEM_INTCOM_RESPONSE_ERR;}

	// Encrypt & Write
	unsigned char aesKey[32];
	getStorageKey(aesKey, upk, sze);
	struct AES_ctx aes;
	AES_init_ctx(&aes, aesKey);
	sodium_memzero(aesKey, 32);

	for (ssize_t i = 0; i < sze + AEM_MSG_MINBLOCKS; i++)
		AES_ECB_encrypt(&aes, msg + i * 16);

	sodium_memzero(&aes, sizeof(struct AES_ctx));

	if (write(fdMsg, msg, (sze + AEM_MSG_MINBLOCKS) * 16) != (ssize_t)((sze + AEM_MSG_MINBLOCKS) * 16)) {close(fdMsg); syslog(LOG_ERR, "storage_write(): Failed write: %m"); return AEM_INTCOM_RESPONSE_ERR;}

	if (isTrash) {
		close(fdMsg);
		saveStindex();
		return AEM_INTCOM_RESPONSE_OK;
	}

	if (num == -1) {
		stindexCount++;
		struct aem_stindex *stindex2 = realloc(stindex, sizeof(struct aem_stindex) * stindexCount);
		if (stindex2 == NULL) {
			syslog(LOG_ERR, "Failed allocation");
			if (ftruncate(fdMsg, oldFilesize) != 0) syslog(LOG_ERR, "Failed ftruncate()");
			close(fdMsg);
			return AEM_INTCOM_RESPONSE_ERR;
		}
		stindex = stindex2;

		num = stindexCount - 1;
		memcpy(stindex[num].pubkey, upk, crypto_box_PUBLICKEYBYTES);
		stindex[num].msgCount = 0;
		stindex[num].msg = malloc(2);
		if (stindex[num].msg == NULL) {
			syslog(LOG_ERR, "Failed allocation");
			if (ftruncate(fdMsg, oldFilesize) != 0) syslog(LOG_ERR, "Failed ftruncate()");
			close(fdMsg);
			return AEM_INTCOM_RESPONSE_ERR;
		}
	} else {
		uint16_t * const newMsg = realloc(stindex[num].msg, (stindex[num].msgCount + 1) * 2);
		if (newMsg == NULL) {
			syslog(LOG_ERR, "Failed allocation");
			if (ftruncate(fdMsg, oldFilesize) != 0) syslog(LOG_ERR, "Failed ftruncate()");
			close(fdMsg);
			return AEM_INTCOM_RESPONSE_ERR;
		}
		stindex[num].msg = newMsg;
	}

	close(fdMsg);
	stindex[num].msg[stindex[num].msgCount] = sze;
	stindex[num].msgCount++;
	saveStindex();
	return AEM_INTCOM_RESPONSE_OK;
}

// Setup/free-up functions

static int loadStindex(void) {
	const int fd = open("Stindex.aem", O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) return -1;

	const off_t sz = lseek(fd, 0, SEEK_END);
	if (sz == 0) {
		close(fd);
		stindexCount = 0;
		stindex = malloc(1);
		return (stindex == NULL) ? -1 : 0;
	}

	unsigned char * const encd = malloc(sz);
	if (encd == NULL) {close(fd); return -1;}

	if (pread(fd, encd, sz, 0) != sz) {free(encd); close(fd); return -1;}
	close(fd);

	unsigned char data[sz];
	if (crypto_secretbox_open_easy(data, encd + crypto_secretbox_NONCEBYTES, sz - crypto_secretbox_NONCEBYTES, encd, stindexKey) != 0) {free(encd); return -1;}
	free(encd);

	memcpy(&stindexCount, data, 2);
	size_t skip = 2;

	stindex = malloc(sizeof(struct aem_stindex) * stindexCount);
	if (stindex == NULL) return -1;

	for (int i = 0; i < stindexCount; i++) {
		stindex[i].level = 0;

		memcpy(stindex[i].pubkey, data + skip, crypto_box_PUBLICKEYBYTES);
		skip += crypto_box_PUBLICKEYBYTES;

		memcpy(&(stindex[i].msgCount), data + skip, 2);
		skip += 2;

		stindex[i].msg = malloc(stindex[i].msgCount * 2);
		if (stindex[i].msg == NULL) {
			for (int j = 0; j < i; j++) free(stindex[j].msg);
			free(stindex);
			return -1;
		}

		for (int j = 0; j < stindex[i].msgCount; j++) {
			memcpy((unsigned char*)stindex[i].msg + (j * 2), data + skip, 2);
			skip += 2;
		}
	}

	return 0;
}

int ioSetup(const unsigned char * const newStorageKey) {
	memcpy(storageKey, newStorageKey, AEM_LEN_KEY_STO);
	crypto_kdf_derive_from_key(stindexKey, AEM_LEN_KEY_STI, 1, "AEM-Sti0", storageKey);
	return loadStindex();
}

static void freeStindex(void) {
	for (int i = 0; i < stindexCount; i++) {
		sodium_memzero(stindex[i].msg, stindex[i].msgCount * 2);
		free(stindex[i].msg);
	}

	sodium_memzero(stindex, stindexCount * sizeof(struct aem_stindex));
	free(stindex);
}

void ioFree(void) {
	sodium_memzero(stindexKey, 32);
	sodium_memzero(storageKey, 32);
	freeStindex();
}
