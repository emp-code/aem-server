#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/AEM_KDF.h"
#include "../Common/Envelope.h"
#include "../Common/Message.h"
#include "../Common/Signature.h"
#include "../Common/memeq.h"
#include "../Data/welcome.h"
#include "../IntCom/Client.h"

#include "IO.h"

#define AEM_MSG_STORAGE_EMPTY (const unsigned char * const)"Storage emptied\nAs you requested, your storage has been emptied.\nAs this is your oldest message now, it can only be deleted by emptying your storage again.\nThis is an automatically generated system message."
#define AEM_MSG_STORAGE_EMPTY_LEN 206

uint16_t stindex_count[AEM_USERCOUNT];

struct {
	uint16_t *id; // EnvelopeID
	uint16_t *bc; // Block count
} stindex[AEM_USERCOUNT];

static unsigned char sbk[AEM_KDF_SUB_KEYLEN];
static unsigned char limits[] = {0,0,0,0}; // 0-255 MiB

// uid: UserID; eid: Encoded UserID
#define AEM_PATH_STO_MSG (char[]){'/','M','s','g','/', eid_chars[uid & 63], eid_chars[(uid >> 6) & 63], '\0'}
static char eid_chars[64] = "????????????????????????????????????????????????????????????????";

// Create a secret encoding based on the key
static void eidSetup(void) {
	const char b64_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_+";
	uint64_t done = 0;

	uint8_t src[8192];
	aem_kdf_sub(src, 8192, AEM_KDF_KEYID_STO_EID, sbk);

	for (int charsDone = 0; charsDone < 64; charsDone++) {
		for (int n = 0; n < 8192; n++) {
			src[n] &= 63;

			if (((done >> src[n]) & 1) == 0) {
				eid_chars[charsDone] = b64_set[src[n]];
				done |= 1UL << src[n];
				break;
			}
		}
	}

	sodium_memzero(src, 8192);
}

static int loadStindex(void) {
	const int fd = open("Stindex.aem", O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "Failed opening Stindex.aem: %m"); return -1;}

	off_t fileSize = lseek(fd, 0, SEEK_END);
	if (fileSize < 1) {syslog(LOG_ERR, "Failed getting size of Stindex.aem"); close(fd); return -1;}

	unsigned char * const enc = malloc(fileSize);
	if (enc == NULL) {syslog(LOG_ERR, "Failed allocation"); close(fd); return -1;}
	if (pread(fd, enc, fileSize, 0) != fileSize) {syslog(LOG_ERR, "Failed reading Stindex.aem"); free(enc); close(fd); return -1;}

	unsigned char stiKey[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_sub(stiKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_STO_STI, sbk);

	unsigned char * const dec = malloc(fileSize - crypto_aead_aegis256_NPUBBYTES - crypto_aead_aegis256_ABYTES);
	if (crypto_aead_aegis256_decrypt(dec, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, fileSize - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, stiKey) == -1) {syslog(LOG_ERR, "Failed decrypting Stindex.aem"); free(enc); close(fd); return -1;}
	free(enc);

	off_t offset = AEM_USERCOUNT * sizeof(uint16_t);
	for (int uid = 0; uid < AEM_USERCOUNT; uid++) {
		stindex_count[uid] = *(uint16_t*)(dec + (uid * sizeof(uint16_t)));

		if (stindex_count[uid] > 0) {
			const size_t bytes = stindex_count[uid] * sizeof(uint16_t);

			stindex[uid].bc = malloc(bytes);
			if (stindex[uid].bc == NULL) {free(dec); close(fd); return -1;}
			stindex[uid].id = malloc(bytes);
			if (stindex[uid].id == NULL) {free(dec); close(fd); return -1;}

			memcpy(stindex[uid].bc, dec + offset, bytes);
			offset += bytes;
			memcpy(stindex[uid].id, dec + offset, bytes);
			offset += bytes;
		}
	}

	free(dec);
	close(fd);
	return 0;
}

static void saveStindex(void) {
	size_t lenDec = AEM_USERCOUNT * sizeof(uint16_t);
	for (int uid = 0; uid < AEM_USERCOUNT; uid++) {
		lenDec += stindex_count[uid] * sizeof(uint16_t) * 2;
	}

	unsigned char * const dec = malloc(lenDec);
	memcpy(dec, (unsigned char*)stindex_count, AEM_USERCOUNT * sizeof(uint16_t));
	size_t offset = AEM_USERCOUNT * sizeof(uint16_t);

	for (int uid = 0; uid < AEM_USERCOUNT; uid++) {
		if (stindex_count[uid] > 0) {
			memcpy(dec + offset, stindex[uid].bc, stindex_count[uid] * sizeof(uint16_t));
			offset += stindex_count[uid] * sizeof(uint16_t);
			memcpy(dec + offset, stindex[uid].id, stindex_count[uid] * sizeof(uint16_t));
			offset += stindex_count[uid] * sizeof(uint16_t);
		}
	}

	const size_t lenEnc = lenDec + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char * const enc = malloc(lenEnc);
	if (enc == NULL) {syslog(LOG_ERR, "Failed allocation"); free(dec); return;}
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);

	unsigned char stiKey[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_sub(stiKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_STO_STI, sbk);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, dec, lenDec, NULL, 0, NULL, enc, stiKey);
	sodium_memzero(stiKey, crypto_aead_aegis256_KEYBYTES);
	sodium_memzero(dec, lenDec);
	free(dec);

	const int fd = open("Stindex.aem", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {
		free(enc);
		syslog(LOG_ERR, "Failed opening Stindex.aem: %m");
		return;
	}

	const ssize_t ret = write(fd, enc, lenEnc);
	free(enc);
	if (ret != (ssize_t)lenEnc) syslog(LOG_ERR, "Failed writing Stindex.aem: %m");
	close(fd);
}

void ioSetup(const unsigned char baseKey[AEM_KDF_SUB_KEYLEN]) {
	memcpy(sbk, baseKey, AEM_KDF_SUB_KEYLEN);
	eidSetup();
	loadStindex();
}

void ioFree(void) {
	sodium_memzero(sbk, AEM_KDF_SUB_KEYLEN);

	for (int uid = 0; uid < AEM_USERCOUNT; uid++) {
		if (stindex_count[uid] > 0) {
			free(stindex[uid].id);
			free(stindex[uid].bc);
		}
	}
}

static size_t getUserStorageAmount(const uint16_t uid) {
	struct stat sb;
	return (lstat(AEM_PATH_STO_MSG, &sb) == 0) ? sb.st_size : 0;
}

int32_t acc_storage_amount(unsigned char ** const res) {
	*res = malloc(AEM_USERCOUNT * sizeof(uint32_t));
	if (*res == NULL) {syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}

	for (int i = 0; i < AEM_USERCOUNT; i++) {
		const size_t bytes = getUserStorageAmount(i);
		const uint32_t blocks = bytes / AEM_EVP_BLOCKSIZE;
		memcpy(*res + i * sizeof(uint32_t), (const unsigned char * const)&blocks, sizeof(uint32_t));
	}

	return AEM_USERCOUNT * sizeof(uint32_t);
}

static unsigned char *sysMsg(const unsigned char * const content, const size_t lenContent, const struct evpKeys * const ek, size_t * const lenResult) {
	const size_t lenMsg = AEM_MSG_HDR_SZ + 1 + lenContent;
	unsigned char msg[lenMsg];
	aem_msg_init(msg, AEM_MSG_TYPE_INT, 0);

	msg[AEM_MSG_HDR_SZ] = 192; // IntMsg InfoByte: System
	memcpy(msg + AEM_MSG_HDR_SZ + 1, content, lenContent);

	aem_sign_message(msg, lenMsg, ek->usk);
	return msg2evp(msg, lenMsg, ek->pwk, NULL, 0, lenResult);
}

int32_t acc_storage_create(const unsigned char * const msg, const size_t lenMsg) {
	if (lenMsg != sizeof(uint16_t) + X25519_PKBYTES) return AEM_INTCOM_RESPONSE_ERR;

	const uint16_t uid = *(const uint16_t * const)msg & 4095;
	if (stindex_count[uid] > 0) return AEM_INTCOM_RESPONSE_EXIST;

	size_t lenWm = 0;
	unsigned char * const wm = sysMsg(AEM_WELCOME, AEM_WELCOME_LEN, (const struct evpKeys * const)msg + sizeof(uint16_t), &lenWm);
	if (wm == NULL) return AEM_INTCOM_RESPONSE_ERR;
	const uint16_t wmBc = (lenWm / AEM_EVP_BLOCKSIZE) - AEM_EVP_MINBLOCKS;

	const int fd = open(AEM_PATH_STO_MSG, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		syslog(LOG_ERR, "Failed creating file: %m");
		free(wm);
		return AEM_INTCOM_RESPONSE_ERR;
	}

	const ssize_t lenWritten = write(fd, wm, lenWm);
	if (lenWritten < 0) syslog(LOG_ERR, "Failed writing file: %m");
	free(wm);
	close(fd);

	if (lenWritten != (ssize_t)lenWm) {
		if (lenWritten >= 0) syslog(LOG_ERR, "Failed writing file: %zd/%zu", lenWritten, lenWm);
		return AEM_INTCOM_RESPONSE_ERR;
	}

	stindex[uid].bc = malloc(sizeof(uint16_t));
	if (stindex[uid].bc == NULL) return AEM_INTCOM_RESPONSE_ERR;
	stindex[uid].id = malloc(sizeof(uint16_t));
	if (stindex[uid].id == NULL) return AEM_INTCOM_RESPONSE_ERR;

	stindex[uid].bc[0] = wmBc;
	stindex[uid].id[0] = 0;
	stindex_count[uid] = 1;
	saveStindex();

	return AEM_INTCOM_RESPONSE_OK;
}

int32_t acc_storage_delete(const unsigned char * const msg, const size_t lenMsg) {
	if (lenMsg != sizeof(uint16_t)) return AEM_INTCOM_RESPONSE_ERR;
	const uint16_t uid = *(const uint16_t * const)msg;
	if (uid > 4095) return AEM_INTCOM_RESPONSE_ERR;

	if (stindex_count[uid] == 0) {
		// This user doesn't seem to have storage at all. This shouldn't happen. We'll try removing their file anyway.
		unlink(AEM_PATH_STO_MSG);
		syslog(LOG_WARNING, "Deleting account with no storage file");
		return AEM_INTCOM_RESPONSE_OK;
	}

	sodium_memzero((unsigned char*)stindex[uid].bc, sizeof(uint16_t) * stindex_count[uid]);
	sodium_memzero((unsigned char*)stindex[uid].id, sizeof(uint16_t) * stindex_count[uid]);
	free(stindex[uid].bc);
	free(stindex[uid].id);
	stindex_count[uid] = 0;
	saveStindex();

	const int r = unlink(AEM_PATH_STO_MSG);
	if (r != 0) {
		syslog(LOG_ERR, "Failed deleting %s: %m", AEM_PATH_STO_MSG);
		return AEM_INTCOM_RESPONSE_ERR;
	}

	return AEM_INTCOM_RESPONSE_OK;
}

int32_t acc_storage_limits(const unsigned char * const new, const size_t lenNew) {
	if (lenNew != 4) return AEM_INTCOM_RESPONSE_ERR;
	memcpy(limits, new, lenNew);
	return AEM_INTCOM_RESPONSE_OK;
}

// Total amount and size of messages
static void browse_infoBytes(unsigned char * const out, const uint16_t uid) {
	uint32_t blocks = 0;
	for (int i = 0; i < stindex_count[uid]; i++) {
		blocks += stindex[uid].bc[i] + AEM_EVP_MINBLOCKS;
	}

	memcpy(out, (const unsigned char * const)&stindex_count[uid], sizeof(uint16_t));
	memcpy(out + sizeof(uint16_t), (unsigned char*)&blocks, sizeof(uint32_t));
}

int32_t api_message_browse(const unsigned char * const req, const size_t lenReq, unsigned char ** const out, const bool newer) {
	if (lenReq != sizeof(uint16_t) && lenReq != sizeof(uint16_t) * 2) return AEM_INTCOM_RESPONSE_USAGE;
	uint16_t uid;
	memcpy((unsigned char*)&uid, req, sizeof(uint16_t));

	int startNum = 0;
	if (lenReq != sizeof(uint16_t)) {
		uint16_t reqId;
		memcpy((unsigned char*)&reqId, req + sizeof(uint16_t), sizeof(uint16_t));

		startNum = -1;

		for (int i = stindex_count[uid] - 1; i >= 0; i--) {
			if (reqId == stindex[uid].id[i]) {
				startNum = i;
				break;
			}
		}

		if (startNum == -1) return AEM_INTCOM_RESPONSE_NOTEXIST;

		if (newer) {
			startNum++;
			if (startNum == stindex_count[uid]) return AEM_INTCOM_RESPONSE_OK; // Found, but nothing newer
		} else {
			if (startNum == 0) return AEM_INTCOM_RESPONSE_OK; // Found, but nothing older

			startNum--;
			for (size_t lenTotal = 0; startNum > 0; startNum--) {
				lenTotal += (stindex[uid].bc[startNum] + AEM_EVP_MINBLOCKS) * AEM_EVP_BLOCKSIZE;
				if (lenTotal > AEM_EVP_MAXSIZE) {
					startNum++;
					break;
				}
			}
		}
	} else if (newer) {
		size_t lenTotal = 0;
		for (startNum = stindex_count[uid] - 1; startNum > 0; startNum--) {
			lenTotal += (stindex[uid].bc[startNum] + AEM_EVP_MINBLOCKS) * AEM_EVP_BLOCKSIZE;
			if (lenTotal > AEM_EVP_MAXSIZE) {
				startNum++;
				break;
			}
		}
	}

	off_t readPos = 0;
	if (startNum != 0) {
		for (int i = 0; i < startNum; i++) {
			readPos += (stindex[uid].bc[i] + AEM_EVP_MINBLOCKS) * AEM_EVP_BLOCKSIZE;
		}
	}

	// Create response
	uint16_t evpCount = 0;
	ssize_t evpBytes = 0;
	for(int i = startNum; i < stindex_count[uid]; i++) {
		if (evpBytes + ((stindex[uid].bc[i] + AEM_EVP_MINBLOCKS) * AEM_EVP_BLOCKSIZE) > AEM_EVP_MAXSIZE) break;

		evpCount++;
		evpBytes += (stindex[uid].bc[i] + AEM_EVP_MINBLOCKS) * AEM_EVP_BLOCKSIZE;
	}

	*out = malloc(6 + sizeof(uint16_t) + (sizeof(uint16_t) * evpCount) + evpBytes);
	if (*out == NULL) {syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}
	browse_infoBytes(*out, uid);
	memcpy(*out + 6, &evpCount, sizeof(uint16_t));
	memcpy(*out + 6 + sizeof(uint16_t), (unsigned char*)stindex[uid].bc + (startNum * sizeof(uint16_t)), evpCount * sizeof(uint16_t));

	const int fd = open(AEM_PATH_STO_MSG, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {
		syslog(LOG_ERR, "Failed opening %s: %m", AEM_PATH_STO_MSG);
		free(*out);
		*out = NULL;
		return AEM_INTCOM_RESPONSE_ERR;
	}

	const ssize_t readBytes = pread(fd, *out + 6 + sizeof(uint16_t) + (evpCount * sizeof(uint16_t)), evpBytes, readPos);
	if (readBytes < 0) syslog(LOG_ERR, "Failed read: %m");
	close(fd);

	if (readBytes != evpBytes) {
		if (readBytes >= 0) syslog(LOG_ERR, "Failed read: %d/%d", readBytes, evpBytes);

		if (readBytes < AEM_EVP_MINBLOCKS * AEM_EVP_BLOCKSIZE) {
			free(*out);
			*out = NULL;
			return AEM_INTCOM_RESPONSE_ERR;
		}
	}

	return 6 + sizeof(uint16_t) + (sizeof(uint16_t) * evpCount) + evpBytes;
}

int32_t storage_delete(const uint16_t uid, const uint16_t delId) {
	const int fdMsg = open(AEM_PATH_STO_MSG, O_RDWR | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fdMsg < 0) {syslog(LOG_ERR, "Failed opening %s: %m", AEM_PATH_STO_MSG); return AEM_INTCOM_RESPONSE_ERR;}

	off_t lenExpected = 0;
	for (int i = 0; i < stindex_count[uid]; i++) {
		lenExpected += (stindex[uid].bc[i] + AEM_EVP_MINBLOCKS) * AEM_EVP_BLOCKSIZE;
	}

	const off_t fileSz = lseek(fdMsg, 0, SEEK_END);
	if (fileSz != lenExpected) {
		syslog(LOG_ERR, "Delete: File %s size differs from expected: %d/%d", AEM_PATH_STO_MSG, fileSz, lenExpected);
		close(fdMsg);
		return AEM_INTCOM_RESPONSE_ERR;
	}

	off_t filePos = 0;
	for (int i = 0; i < stindex_count[uid]; i++) {
		const size_t evpBytes = (stindex[uid].bc[i] + AEM_EVP_MINBLOCKS) * AEM_EVP_BLOCKSIZE;

		if (stindex[uid].id[i] != delId) {
			filePos += evpBytes;
			continue;
		}

		// ID matches
		if (i == stindex_count[uid] - 1) {
			// Latest message - truncate only
			if (ftruncate(fdMsg, fileSz - evpBytes) != 0) {
				syslog(LOG_ERR, "Delete: Failed ftruncate: %m");
				close(fdMsg);
				return AEM_INTCOM_RESPONSE_ERR;
			}

			stindex_count[uid]--;
			close(fdMsg);
			saveStindex();
			return AEM_INTCOM_RESPONSE_OK;
		}

		const off_t szOverwrite = fileSz - filePos - evpBytes;
		unsigned char * const tmp = malloc(szOverwrite);
		if (tmp == NULL) {
			syslog(LOG_ERR, "Failed malloc");
			close(fdMsg);
			return AEM_INTCOM_RESPONSE_ERR;
		}

		if (pread(fdMsg, tmp, szOverwrite, filePos + evpBytes) != szOverwrite) {
			syslog(LOG_ERR, "Delete: Failed read: %m");
			free(tmp);
			close(fdMsg);
			return AEM_INTCOM_RESPONSE_ERR;
		}

		if (pwrite(fdMsg, tmp, szOverwrite, filePos) != szOverwrite) {
			syslog(LOG_ERR, "Delete: Failed write: %m");
			free(tmp);
			close(fdMsg);
			return AEM_INTCOM_RESPONSE_ERR;
		}

		free(tmp);

		if (ftruncate(fdMsg, fileSz - evpBytes) != 0) {
			syslog(LOG_ERR, "Delete: Failed ftruncate: %m");
			close(fdMsg);
			return AEM_INTCOM_RESPONSE_ERR;
		}

		close(fdMsg);

		memmove((unsigned char*)stindex[uid].bc + (sizeof(uint16_t) * i), (unsigned char*)stindex[uid].bc + (sizeof(uint16_t) * (i + 1)), sizeof(uint16_t) * (stindex_count[uid] - i - 1));
		memmove((unsigned char*)stindex[uid].id + (sizeof(uint16_t) * i), (unsigned char*)stindex[uid].id + (sizeof(uint16_t) * (i + 1)), sizeof(uint16_t) * (stindex_count[uid] - i - 1));
		stindex_count[uid]--;

		saveStindex();
		return AEM_INTCOM_RESPONSE_OK;
	}

	// Not found
	close(fdMsg);
	return AEM_INTCOM_RESPONSE_NOTEXIST;
}

int32_t storage_write(unsigned char * const msg, const size_t lenMsg, const uint16_t uid) {
	if (lenMsg < (AEM_EVP_MINBLOCKS * AEM_EVP_BLOCKSIZE) || lenMsg > AEM_MSG_W_MAXSIZE) {syslog(LOG_ERR, "Invalid incoming message size: %zu", lenMsg); return AEM_INTCOM_RESPONSE_ERR;}
	if (stindex_count[uid] == 0) {syslog(LOG_ERR, "Incoming message for nonexistent user: %u", uid); return AEM_INTCOM_RESPONSE_ERR;}

	// Get the user's Envelope Keys from AEM-Account. sign the Message and turn it into an Envelope
	unsigned char *ek_raw = NULL;
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_ACC, uid, NULL, 0, &ek_raw, sizeof(struct evpKeys));
	if (icRet != sizeof(struct evpKeys)) {
		if (ek_raw != NULL) free(ek_raw);
		syslog(LOG_ERR, "Failed getting EK from Account: %d", icRet);
		return AEM_INTCOM_RESPONSE_ERR;
	}
	const struct evpKeys * const ek = (const struct evpKeys * const)ek_raw;

	aem_sign_message(msg, lenMsg, ek->usk);
	size_t lenEvp;
	unsigned char * const evp = msg2evp(msg, lenMsg, ek->pwk, stindex[uid].id, stindex_count[uid], &lenEvp);

	sodium_memzero(ek_raw, sizeof(struct evpKeys));
	free(ek_raw);
	if (evp == NULL) {syslog(LOG_ERR, "Failed making evp"); return AEM_INTCOM_RESPONSE_ERR;}

	// Stindex
	uint16_t *new = reallocarray(stindex[uid].bc, stindex_count[uid] + 1, sizeof(uint16_t));
	if (new == NULL) {syslog(LOG_ERR, "Failed malloc"); free(evp); return AEM_INTCOM_RESPONSE_ERR;}
	stindex[uid].bc = new;

	new = reallocarray(stindex[uid].id, stindex_count[uid] + 1, sizeof(uint16_t));
	if (new == NULL) {syslog(LOG_ERR, "Failed malloc"); free(evp); return AEM_INTCOM_RESPONSE_ERR;}
	stindex[uid].id = new;

	const uint16_t evpId = getEnvelopeId(evp);
	stindex[uid].bc[stindex_count[uid]] = (lenEvp / AEM_EVP_BLOCKSIZE) - AEM_EVP_MINBLOCKS;
	stindex[uid].id[stindex_count[uid]] = evpId;

	// Write to disk
	const int fd = open(AEM_PATH_STO_MSG, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "storage_write(): Failed open: %m"); free(evp); return AEM_INTCOM_RESPONSE_ERR;}

	const ssize_t evpBytes = (stindex[uid].bc[stindex_count[uid]] + AEM_EVP_MINBLOCKS) * AEM_EVP_BLOCKSIZE;
	const ssize_t wroteBytes = write(fd, evp, evpBytes);
	if (wroteBytes < 0) syslog(LOG_ERR, "storage_write(): Failed write: %m");
	close(fd);

	if (wroteBytes != evpBytes) {
		if (wroteBytes >= 0) syslog(LOG_ERR, "storage_write(): Failed write: %zd/%zd", wroteBytes, evpBytes);
		free(evp);
		return AEM_INTCOM_RESPONSE_ERR;
	}

	// Finish
	stindex_count[uid]++;
	saveStindex();
	free(evp);

	return evpId - (UINT16_MAX + 1); // Returns the EnvelopeID as a negative pseudo-errorcode
}

int32_t storage_empty(const uint16_t uid) {
	unsigned char *ek = NULL;
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_ACC, uid, NULL, 0, &ek, sizeof(struct evpKeys));
	if (icRet != sizeof(struct evpKeys)) {syslog(LOG_ERR, "Failed getting EK from Account: %d", icRet); return AEM_INTCOM_RESPONSE_ERR;}

	size_t lenEvp = 0;
	unsigned char * const evp = sysMsg(AEM_MSG_STORAGE_EMPTY, AEM_MSG_STORAGE_EMPTY_LEN, (const struct evpKeys * const)ek, &lenEvp);
	sodium_memzero(ek, sizeof(struct evpKeys));
	free(ek);

	if (evp == NULL) return AEM_INTCOM_RESPONSE_ERR;
	const uint16_t evpBc = (lenEvp / AEM_EVP_BLOCKSIZE) - AEM_EVP_MINBLOCKS;

	const int fd = open(AEM_PATH_STO_MSG, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "Failed opening %s: %m", AEM_PATH_STO_MSG); free(evp); return AEM_INTCOM_RESPONSE_ERR;}

	const ssize_t lenWritten = write(fd, evp, lenEvp);
	if (lenWritten < 0) syslog(LOG_ERR, "Failed writing file: %m");
	free(evp);
	close(fd);

	if (lenWritten != (ssize_t)lenEvp) {
		if (lenWritten >= 0) syslog(LOG_ERR, "Failed writing file: %zd/%zu", lenWritten, lenEvp);
		return AEM_INTCOM_RESPONSE_ERR;
	}

	sodium_memzero((unsigned char*)stindex[uid].bc, sizeof(uint16_t) * stindex_count[uid]);
	sodium_memzero((unsigned char*)stindex[uid].id, sizeof(uint16_t) * stindex_count[uid]);

	stindex[uid].bc[0] = evpBc;
	stindex[uid].id[0] = 0;
	stindex_count[uid] = 1;
	saveStindex();	
	return AEM_INTCOM_RESPONSE_OK;
}
