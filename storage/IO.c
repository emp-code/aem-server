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

uint16_t getStindexCount(void) {
	return stindexCount;
}

int updateLevels(const unsigned char * const data, const size_t lenData) {
	if (lenData % (crypto_box_PUBLICKEYBYTES + 1) != 0) {syslog(LOG_ERR, "updateLevels(): Invalid format"); return -1;}

	int recCount = lenData / (crypto_box_PUBLICKEYBYTES + 1);
	if (recCount < stindexCount) {syslog(LOG_WARNING, "updateLevels(): Lower accounts than stindexCount");}
	else if (recCount > stindexCount) recCount = stindexCount;

	for (int i = 0; i < stindexCount && i < recCount; i++) {
		if (memcmp(data + (i * (crypto_box_PUBLICKEYBYTES + 1)) + 1, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) { // In sync
			stindex[i].level = data[i * (crypto_box_PUBLICKEYBYTES + 1)];
		} else { // Out of sync
			bool found = false;
			stindex[i].level = 0;

			for (int j = 0; j < recCount; j++) {
				if (memcmp(data + (j * (crypto_box_PUBLICKEYBYTES + 1)) + 1, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) {
					found = true;
					stindex[i].level = data[j * (crypto_box_PUBLICKEYBYTES + 1)];
					break;
				}
			}

			syslog(LOG_WARNING, "updateLevels(): Out of sync (%d/%d), %s", i, recCount, found? "found" : "not found");
		}

		if (stindex[i].level > AEM_USERLEVEL_MAX) {
			syslog(LOG_WARNING, "updateLevels(): Max level exceeded: %u, setting to zero", stindex[i].level);
			stindex[i].level = 0;
		}
	}

	return 0;
}

void updateLimits(const unsigned char * const newLimits) {
	memcpy(limits, newLimits, 4);
}

size_t getUserStorageAmount(const int num) {
	size_t total = 0;
	for (int i = 0; i < stindex[num].msgCount; i++) {
		total += stindex[num].msg[i] * 16;
	}
	return total;
}

size_t getStorageAmounts(unsigned char ** const out) {
	const size_t outSize = stindexCount * (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t));
	*out = malloc(outSize);
	if (*out == NULL) return 0;

	for (int i = 0; i < stindexCount; i++) {
		const uint32_t bytes = getUserStorageAmount(i);
		memcpy(*out + i * (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t)), (unsigned char*)&bytes, sizeof(uint32_t));
		memcpy(*out + i * (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t)) + sizeof(uint32_t), stindex[i].pubkey, crypto_box_PUBLICKEYBYTES);
	}

	return outSize;
}

static void getStorageKey(unsigned char * const target, const unsigned char * const upk, const uint16_t sze) {
	uint64_t keyId;
	memcpy(&keyId, &sze, 2);
	memcpy((unsigned char*)&keyId + 2, upk, 6);

	// Uses random key for 'Trash'; the extra kdf/random is to resist timing attacks
	unsigned char empty[crypto_box_PUBLICKEYBYTES];
	memset(empty, 0xFF, crypto_box_PUBLICKEYBYTES);
	if (memcmp(empty, upk, crypto_box_PUBLICKEYBYTES) == 0) {
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

	if (memcmp(empty, upk, crypto_box_PUBLICKEYBYTES) == 0) {
		strcpy(path, "MessageData/Trash");
	} else {
		memcpy(path, "MessageData/", 12);
	}
}

static void browse_infoBytes(unsigned char * const target, const int stindexNum) {
	const uint16_t count = stindex[stindexNum].msgCount;

	uint32_t blocks = 0;
	for (int i = 0; i < stindex[stindexNum].msgCount; i++) {
		blocks += stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS;
	}

	memcpy(target, &count, 2);
	memcpy(target + 2, &blocks, 4);
}

// Public functions

int storage_erase(const unsigned char * const upk) {
	char path[77];
	getMsgPath(path, upk);
	int unlinkRet = unlink(path);
	if (unlinkRet == -1 && errno == ENOENT) unlinkRet = 0; // Treat file not existing (no message data to delete) as success

	int delNum = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memcmp(stindex[i].pubkey, upk, crypto_box_PUBLICKEYBYTES) == 0) {
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

	return unlinkRet;
}

int storage_delete(const unsigned char upk[crypto_box_PUBLICKEYBYTES], const unsigned char * const id) {
	int stindexNum = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memcmp(upk, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) {
			stindexNum = i;
			break;
		}
	}

	if (stindexNum == -1) {syslog(LOG_NOTICE, "Invalid pubkey in delete request"); return -1;}

	char path[77];
	getMsgPath(path, stindex[stindexNum].pubkey);

	const int fdMsg = open(path, O_RDWR | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fdMsg < 0) return fdMsg;

	off_t filePos = lseek(fdMsg, 0, SEEK_END);
	const off_t fileSize = filePos;
	bool doneDelete = false;

	for (int i = stindex[stindexNum].msgCount - 1; i >= 0; i--) {
		filePos -= (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;

		if (!idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, id)) continue;
		doneDelete = true;

		// ID matches
		if (i < stindex[stindexNum].msgCount - 1) {
			// Messages to preserve after this one
			const off_t readPos = filePos + (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;

			const ssize_t readAmount = fileSize - readPos;
			unsigned char * const buf = malloc(readAmount);
			if (buf == NULL) {close(fdMsg); return -1;}

			const ssize_t readBytes = pread(fdMsg, buf, readAmount, readPos);
			if (readBytes != readAmount) {
				close(fdMsg);
				free(buf);
				syslog(LOG_ERR, "storage_delete: Failed read()");
				return -1;
			}

			const ssize_t writtenBytes = pwrite(fdMsg, buf, readAmount, filePos);
			free(buf);
			if (writtenBytes != readAmount) {
				close(fdMsg);
				syslog(LOG_ERR, "storage_delete: Failed write()");
				return -1;
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
	return doneDelete ? 0 : -100;
}

int storage_write(const unsigned char upk[crypto_box_PUBLICKEYBYTES], unsigned char * const data, const uint16_t sze) {
	// Stindex
	int num = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memcmp(upk, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) {
			num = i;
			break;
		}
	}

	if (num != -1 && (int)getUserStorageAmount(num) >= (limits[stindex[num].level & 3]) * 1048576) return AEM_STORE_USRFULL; // Over storage limit

	char path[77];
	getMsgPath(path, upk);

	const int fdMsg = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW | ((path[12] == 'T') ? O_TRUNC : O_APPEND), S_IRUSR | S_IWUSR | S_ISVTX);
	if (fdMsg < 0) {syslog(LOG_ERR, "storage_write(): Failed open: %m"); return AEM_STORE_INERROR;}

	const off_t oldFilesize = lseek(fdMsg, 0, SEEK_END);
	if (oldFilesize < 0) {syslog(LOG_ERR, "storage_write(): Failed lseek: %m"); return AEM_STORE_INERROR;}

	// Encrypt & Write
	unsigned char aesKey[32];
	getStorageKey(aesKey, upk, sze);
	struct AES_ctx aes;
	AES_init_ctx(&aes, aesKey);
	sodium_memzero(aesKey, 32);

	for (int i = 0; i < sze + AEM_MSG_MINBLOCKS; i++)
		AES_ECB_encrypt(&aes, data + i * 16);

	sodium_memzero(&aes, sizeof(struct AES_ctx));

	if (write(fdMsg, data, (sze + AEM_MSG_MINBLOCKS) * 16) != (sze + AEM_MSG_MINBLOCKS) * 16) {close(fdMsg); syslog(LOG_ERR, "storage_write(): Failed write: %m"); return AEM_STORE_INERROR;}

	if (path[12] == 'T') {
		close(fdMsg);
		saveStindex();
		return 0;
	}

	if (num == -1) {
		stindexCount++;
		struct aem_stindex *stindex2 = realloc(stindex, sizeof(struct aem_stindex) * stindexCount);
		if (stindex2 == NULL) {
			syslog(LOG_ERR, "Failed allocation");
			if (ftruncate(fdMsg, oldFilesize) != 0) syslog(LOG_ERR, "Failed ftruncate()");
			close(fdMsg);
			return AEM_STORE_INERROR;
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
			return AEM_STORE_INERROR;
		}
	} else {
		uint16_t * const newMsg = realloc(stindex[num].msg, (stindex[num].msgCount + 1) * 2);
		if (newMsg == NULL) {
			syslog(LOG_ERR, "Failed allocation");
			if (ftruncate(fdMsg, oldFilesize) != 0) syslog(LOG_ERR, "Failed ftruncate()");
			close(fdMsg);
			return AEM_STORE_INERROR;
		}
		stindex[num].msg = newMsg;
	}

	close(fdMsg);
	stindex[num].msg[stindex[num].msgCount] = sze;
	stindex[num].msgCount++;
	saveStindex();
	return 0;
}

int storage_read(const unsigned char * const upk, const unsigned char * const matchId, unsigned char ** const msgData) {
	int stindexNum = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memcmp(stindex[i].pubkey, upk, crypto_box_PUBLICKEYBYTES) == 0) {
			stindexNum = i;
			break;
		}
	}

	if (stindexNum < 0) return 0; // Stindex for account doesn't exist (new account, no messages received yet)

	*msgData = sodium_malloc(AEM_MAXLEN_MSGDATA);
	if (*msgData == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}
	bzero(*msgData, AEM_MAXLEN_MSGDATA);
	browse_infoBytes(*msgData, stindexNum);

	char path[77];
	getMsgPath(path, stindex[stindexNum].pubkey);

	const int fdMsg = open(path, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fdMsg < 0) return -1;

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

			if (stopIndex == -1) {close(fdMsg); return -1;} // matchId not found
			filePos = lseek(fdMsg, 0, SEEK_END);
		} else { // older
			startIndex = 0;

			const off_t startFilePos = (stindex[stindexNum].msg[0] + AEM_MSG_MINBLOCKS) * 16;
			filePos = lseek(fdMsg, startFilePos, SEEK_SET);
			if (filePos != startFilePos) {close(fdMsg); return -1;}

			for (int i = 1; i < stindex[stindexNum].msgCount; i++) {
				if (idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, matchId + 1)) {
					startIndex = i - 1;
					break;
				}

				filePos += (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;
			}

			if (startIndex == 0) {close(fdMsg); return -1;} // matchId not found, or is the oldest
		}
	}

	int offset = 6; // browse_infoBytes

	for (int i = startIndex; i > stopIndex; i--) {
		const uint16_t sze = stindex[stindexNum].msg[i];
		if (offset + 2 + ((sze + AEM_MSG_MINBLOCKS) * 16) > AEM_MAXLEN_MSGDATA) break;

		memcpy(*msgData + offset, &sze, 2);
		offset += 2;

		filePos -= (sze + AEM_MSG_MINBLOCKS) * 16;
		if (pread(fdMsg, *msgData + offset, (sze + AEM_MSG_MINBLOCKS) * 16, filePos) != (sze + AEM_MSG_MINBLOCKS) * 16) {
			syslog(LOG_ERR, "Failed read (%d)", sze);
			break;
		}

		unsigned char aesKey[32];
		getStorageKey(aesKey, stindex[stindexNum].pubkey, stindex[stindexNum].msg[i]);
		struct AES_ctx aes;
		AES_init_ctx(&aes, aesKey);
		sodium_memzero(aesKey, 32);

		for (int j = 0; j < (sze + AEM_MSG_MINBLOCKS); j++)
			AES_ECB_decrypt(&aes, *msgData + offset + (j * 16));

		sodium_memzero(&aes, sizeof(struct AES_ctx));

		offset += (sze + AEM_MSG_MINBLOCKS) * 16;
	}

	close(fdMsg);
	return offset;
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
