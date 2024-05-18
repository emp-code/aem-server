#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/AEM_KDF.h"
#include "../Common/Envelope.h"
#include "../Common/Message.h"
#include "../Common/memeq.h"
#include "../Data/welcome.h"
#include "../IntCom/Client.h"

#include "IO.h"

uint16_t stindex_count[AEM_USERCOUNT];
uint16_t *stindex_size[AEM_USERCOUNT];

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
}

static int loadStindex(void) {
	const int fd = open("Stindex.aem", O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "Failed opening Stindex.aem"); return -1;}

	off_t fileSize = lseek(fd, 0, SEEK_END);
	if (fileSize < 1) {syslog(LOG_ERR, "Failed getting size of Stindex.aem"); return -1;}

	unsigned char * const enc = malloc(fileSize);
	if (enc == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}

	if (pread(fd, enc, fileSize, 0) != fileSize) {syslog(LOG_ERR, "Failed reading Stindex.aem"); free(enc); return -1;}

	unsigned char stiKey[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_sub(stiKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_STO_STI, sbk);

	unsigned char * const dec = malloc(fileSize - crypto_aead_aegis256_NPUBBYTES - crypto_aead_aegis256_ABYTES);
	if (crypto_aead_aegis256_decrypt(dec, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, fileSize - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, stiKey) == -1) {syslog(LOG_ERR, "Failed decrypting Stindex.aem"); free(enc); return -1;}
	free(enc);

	for (int uid = 0; uid < AEM_USERCOUNT; uid++) {
		stindex_count[uid] = *(uint16_t*)(dec + (uid * sizeof(uint16_t)));
	}

	off_t offset = AEM_USERCOUNT * sizeof(uint16_t);
	for (int uid = 0; uid < AEM_USERCOUNT; uid++) {
		if (stindex_count[uid] > 0) {
			const size_t sz = stindex_count[uid] * sizeof(uint16_t);
			stindex_size[uid] = malloc(sz);
			memcpy(stindex_size[uid], dec + offset, sz);
			offset += sz;
		}
	}

	free(dec);
	return 0;
}

static void saveStindex(void) {
	unsigned char stx[16384]; // With padding
	memcpy(stx, (unsigned char*)stindex_count, AEM_USERCOUNT * sizeof(uint16_t));
	size_t offset = AEM_USERCOUNT * sizeof(uint16_t);

	for (int i = 0; i < AEM_USERCOUNT; i++) {
		if (stindex_count[i] > 0) {
			memcpy(stx + offset, (unsigned char*)stindex_size[i], stindex_count[i] * sizeof(uint16_t));
			offset += stindex_count[i] * sizeof(uint16_t);
		}
	}

	bzero(stx + offset, 16384 - offset);
	const size_t lenEnc = 16384 + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char * const enc = malloc(lenEnc);
	if (enc == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);

	unsigned char stiKey[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_sub(stiKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_STO_STI, sbk);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, stx, 16384, NULL, 0, NULL, enc, stiKey);
	sodium_memzero(stiKey, crypto_aead_aegis256_KEYBYTES);
	sodium_memzero(stx, 16384);

	const int fd = open("Stindex.aem", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {
		free(enc);
		syslog(LOG_ERR, "Failed opening Account.aem");
		return;
	}

	const ssize_t ret = write(fd, enc, lenEnc);
	free(enc);
	close(fd);

	if (ret != (ssize_t)lenEnc) syslog(LOG_ERR, "Failed writing Stindex.aem");
}

void ioSetup(const unsigned char baseKey[AEM_KDF_SUB_KEYLEN]) {
	memcpy(sbk, baseKey, AEM_KDF_SUB_KEYLEN);
	eidSetup();
	loadStindex();
}

void ioFree(void) {
	sodium_memzero(sbk, AEM_KDF_SUB_KEYLEN);

	for (int uid = 0; uid < AEM_USERCOUNT; uid++) {
		if (stindex_count[uid] > 0) free(stindex_size[uid]);
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
		const uint32_t blocks = bytes / 16;
		memcpy(*res + i * sizeof(uint32_t), (const unsigned char * const)&blocks, sizeof(uint32_t));
	}

	return AEM_USERCOUNT * sizeof(uint32_t);
}

static unsigned char *welcomeEnvelope(const unsigned char epk[X25519_PKBYTES], size_t * const lenEnvelope) {
	const uint32_t ts = (uint32_t)time(NULL);
	*lenEnvelope = AEM_ENVELOPE_RESERVED_LEN + 6 + AEM_WELCOME_LEN;
	const size_t padAmount = msg_getPadAmount(*lenEnvelope);
	*lenEnvelope += padAmount;

	unsigned char * const msg = malloc(*lenEnvelope);
	if (msg == NULL) return NULL;

	msg[AEM_ENVELOPE_RESERVED_LEN] = padAmount | 16; // 16=IntMsg
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 1, &ts, 4);
	msg[AEM_ENVELOPE_RESERVED_LEN + 5] = 192; // IntMsg InfoByte: System
	memcpy(msg + AEM_ENVELOPE_RESERVED_LEN + 6, AEM_WELCOME, AEM_WELCOME_LEN);

	message_into_envelope(msg, *lenEnvelope, epk);
	return msg;
}

int32_t acc_storage_create(const unsigned char * const msg, const size_t lenMsg) {
	if (lenMsg != 2 + X25519_PKBYTES) return AEM_INTCOM_RESPONSE_ERR;

	size_t lenWm = 0;
	unsigned char * const wm = welcomeEnvelope(msg + 2, &lenWm);
	if (wm == NULL) return -1;
	const uint16_t wmBlocks = (lenWm / 16) - AEM_ENVELOPE_MINBLOCKS;

	const uint16_t uid = *(const uint16_t * const)msg & 4095;

	const int fd = open(AEM_PATH_STO_MSG, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		syslog(LOG_ERR, "Failed creating file");
		return AEM_INTCOM_RESPONSE_ERR;
	}

	if (write(fd, wm, lenWm) != (ssize_t)lenWm) {
		close(fd);
		syslog(LOG_ERR, "Failed writing file");
		return AEM_INTCOM_RESPONSE_ERR;
	}

	close(fd);

	stindex_count[uid] = 1;
	stindex_size[uid] = malloc(sizeof(uint16_t));
	if (stindex_size[uid] == NULL) return AEM_INTCOM_RESPONSE_ERR;
	stindex_size[uid][0] = wmBlocks;

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

	sodium_memzero((unsigned char*)stindex_size[uid], sizeof(uint16_t) * stindex_count[uid]);
	free(stindex_size[uid]);
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
		blocks += stindex_size[uid][i] + AEM_ENVELOPE_MINBLOCKS;
	}

	memcpy(out, (const unsigned char * const)&stindex_count[uid], sizeof(uint16_t));
	memcpy(out + sizeof(uint16_t), (unsigned char*)&blocks, sizeof(uint32_t));
}

int32_t api_message_browse(const unsigned char * const req, const size_t lenReq, unsigned char ** const out) {
	if (lenReq != 3 && lenReq != 3 + AEM_API_REQ_DATA_LEN) return AEM_INTCOM_RESPONSE_USAGE;
	uint16_t uid;
	memcpy((unsigned char*)&uid, req, sizeof(uint16_t));

	*out = malloc(AEM_ENVELOPE_MAXSIZE + 8); // 6: InfoBytes, 2: Size of first message
	if (*out == NULL) {syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}
	bzero(*out, AEM_ENVELOPE_MAXSIZE + 8); // random data if pad1m
	browse_infoBytes(*out, uid);

	const int fdMsg = open(AEM_PATH_STO_MSG, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fdMsg < 0) {syslog(LOG_ERR, "Failed opening %s: %m", AEM_PATH_STO_MSG); return AEM_INTCOM_RESPONSE_ERR;}

	off_t filePos = lseek(fdMsg, 0, SEEK_END);

	int startIndex = stindex_count[uid] - 1;
	int stopIndex = -1;

/*	if (matchId != NULL) {
		if (matchId[0] & AEM_FLAG_NEWER) {
			for (int i = stindex[stindexNum].msgCount - 1; i >= 0; i--) {
				filePos -= (stindex[stindexNum].msg[i] + AEM_ENVELOPE_MINBLOCKS) * 16;

				if (idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, matchId + 1)) {
					stopIndex = i;
					break;
				}
			}

			if (stopIndex == -1) {close(fdMsg); return AEM_INTCOM_RESPONSE_NOTEXIST;} // matchId not found
			filePos = lseek(fdMsg, 0, SEEK_END);
		} else { // older
			startIndex = 0;

			const off_t startFilePos = (stindex[stindexNum].msg[0] + AEM_ENVELOPE_MINBLOCKS) * 16;
			filePos = lseek(fdMsg, startFilePos, SEEK_SET);
			if (filePos != startFilePos) {close(fdMsg); return AEM_INTCOM_RESPONSE_ERR;}

			for (int i = 1; i < stindex[stindexNum].msgCount; i++) {
				if (idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, matchId + 1)) {
					startIndex = i - 1;
					break;
				}

				filePos += (stindex[stindexNum].msg[i] + AEM_ENVELOPE_MINBLOCKS) * 16;
			}

			if (startIndex == 0) {close(fdMsg); return AEM_INTCOM_RESPONSE_NOTEXIST;} // matchId not found, or is the oldest
		}
	}
*/
	int offset = 6; // browse_infoBytes

	for (int i = startIndex; i > stopIndex; i--) {
		const uint16_t blocks = stindex_size[uid][i];
		if (offset + 2 + ((blocks + AEM_ENVELOPE_MINBLOCKS) * 16) > AEM_ENVELOPE_MAXSIZE + 8) break;

		memcpy(*out + offset, &blocks, 2);
		offset += 2;

		filePos -= (blocks + AEM_ENVELOPE_MINBLOCKS) * 16;
		if (pread(fdMsg, *out + offset, (blocks + AEM_ENVELOPE_MINBLOCKS) * 16, filePos) != (blocks + AEM_ENVELOPE_MINBLOCKS) * 16) {
			syslog(LOG_ERR, "Failed read");
			break;
		}

		offset += (blocks + AEM_ENVELOPE_MINBLOCKS) * 16;
	}

	close(fdMsg);
	return offset; // full size if pad1m
}

int32_t storage_delete(unsigned char * const delId, const uint16_t uid) {
	const int fdMsg = open(AEM_PATH_STO_MSG, O_RDWR | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fdMsg < 0) {syslog(LOG_ERR, "Failed opening %s: %m", AEM_PATH_STO_MSG); return AEM_INTCOM_RESPONSE_ERR;}

	const off_t fileSz = lseek(fdMsg, 0, SEEK_END);

	unsigned char msgId[16];
	off_t filePos = 0;
	for (int i = 0; i < stindex_count[uid]; i++) {
		if (pread(fdMsg, msgId, 16, filePos) != 16) {
			syslog(LOG_ERR, "Delete: Failed read: %m");
			close(fdMsg);
			return AEM_INTCOM_RESPONSE_ERR;
		}

		if (memeq(msgId, delId, 16)) {
			// ID matches
			const off_t szOverwrite = fileSz - filePos - stindex_size[uid][i];
			unsigned char * const tmp = malloc(szOverwrite);
			if (tmp == NULL) {
				syslog(LOG_ERR, "Failed malloc");
				close(fdMsg);
				return AEM_INTCOM_RESPONSE_ERR;
			}

			if (pread(fdMsg, tmp, szOverwrite, filePos + stindex_size[uid][i]) != szOverwrite) {
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

			if (ftruncate(fdMsg, fileSz - stindex_size[uid][i]) != 0) {
				syslog(LOG_ERR, "Delete: Failed ftruncate: %m");
				close(fdMsg);
				return AEM_INTCOM_RESPONSE_ERR;
			}

			close(fdMsg);

			if (i < stindex_count[uid] - 1) {
				memmove((unsigned char*)stindex_size[uid] + (sizeof(uint16_t) * i), (unsigned char*)stindex_size[uid] + (sizeof(uint16_t) * (i + 1)), sizeof(uint16_t) * (stindex_count[uid] - i - 1));
			}

			stindex_count[uid]--;
			saveStindex();
			return AEM_INTCOM_RESPONSE_OK;
		}

		filePos += stindex_size[uid][i];
	}

	// Not found
	close(fdMsg);
	return AEM_INTCOM_RESPONSE_NOTEXIST;
}

int32_t storage_write(unsigned char * const msg, const size_t lenMsg, const uint16_t uid) {
	if (lenMsg < AEM_ENVELOPE_MINSIZE || lenMsg > AEM_ENVELOPE_MAXSIZE || lenMsg % 16 != 0) {syslog(LOG_ERR, "Invalid incoming message size: %zu", lenMsg); return AEM_INTCOM_RESPONSE_ERR;}
	if (stindex_count[uid] == 0) {syslog(LOG_ERR, "Incoming message for nonexistent user: %u", uid); return AEM_INTCOM_RESPONSE_ERR;}

	// Get user's EPK from AEM-Account. and turn the Message into an Envelope
	unsigned char *epk = NULL;
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_ACC, uid, NULL, 0, &epk, X25519_PKBYTES);
	if (icRet != X25519_PKBYTES) {syslog(LOG_ERR, "Failed getting EPK from Account: %d", icRet); return AEM_INTCOM_RESPONSE_ERR;}

	message_into_envelope(msg, lenMsg, epk);
	sodium_memzero(epk, X25519_PKBYTES);
	free(epk);
	const uint16_t bc = (lenMsg / 16) - AEM_ENVELOPE_MINBLOCKS;

	// Stindex
	uint16_t * const new = reallocarray(stindex_size[uid], stindex_count[uid] + 1, sizeof(uint16_t));
	if (new == NULL) {syslog(LOG_ERR, "Failed malloc"); return AEM_INTCOM_RESPONSE_ERR;}

	stindex_size[uid] = new;
	stindex_size[uid][stindex_count[uid]] = bc;

	// Disk
	const int fd = open(AEM_PATH_STO_MSG, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "storage_write(): Failed open: %m"); return AEM_INTCOM_RESPONSE_ERR;}

	if (write(fd, msg, (bc + AEM_ENVELOPE_MINBLOCKS) * 16) != (ssize_t)((bc + AEM_ENVELOPE_MINBLOCKS) * 16)) {
		close(fd);
		syslog(LOG_ERR, "storage_write(): Failed write: %m");
		return AEM_INTCOM_RESPONSE_ERR;
	}

	close(fd);

	// Finish
	stindex_count[uid]++;
	saveStindex();
	return AEM_INTCOM_RESPONSE_OK;
}
