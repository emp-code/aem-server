#include <fcntl.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h> // for mlockall
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/SetCaps.h"
#include "../Common/aes.h"
#include "../Data/internal.h"

#define AEM_LOGNAME "AEM-Sto"
#define AEM_STINDEX_PAD 1048576 // 1 MiB
#define AEM_SOCK_QUEUE 50

static unsigned char stindexKey[AEM_LEN_KEY_STI];
static unsigned char storageKey[AEM_LEN_KEY_STO];

struct aem_stindex {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	uint16_t msgCount;
	uint16_t *msg;
};

static struct aem_stindex *stindex;
static uint16_t stindexCount;

static bool terminate = false;

static void sigTerm(const int sig) {
	if (sig == SIGUSR1) {
		terminate = true;
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	sodium_memzero(stindexKey, 32);
	sodium_memzero(storageKey, 32);

	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"

static void getStorageKey(unsigned char * const target, const unsigned char * const pubkey, const uint16_t sze) {
	uint64_t keyId;
	memcpy(&keyId, &sze, 2);
	memcpy((unsigned char*)&keyId + 2, pubkey, 6);

	crypto_kdf_derive_from_key(target, 32, keyId, "AEM-Sto0", storageKey);
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

static bool storage_idMatch(const int fdMsg, const int stindexNum, const int sze, const int pos, const unsigned char * const id) {
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
static void getMsgPath(char path[77], const unsigned char pubkey[crypto_box_PUBLICKEYBYTES]) {
	unsigned char aesKey[32];
	struct AES_ctx aes;

	crypto_kdf_derive_from_key(aesKey, 32, 1, "AEM-Stp0", storageKey);
	AES_init_ctx(&aes, aesKey);

	unsigned char pkEnc[32];
	memcpy(pkEnc, pubkey, 32);
	AES_ECB_encrypt(&aes, pkEnc);
	AES_ECB_encrypt(&aes, pkEnc + 16);

	memcpy(path, "MessageData/", 12);
	sodium_bin2hex(path + 12, 65, pkEnc, 32);
}

static int storage_write(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], unsigned char * const data, const uint16_t sze) {
	char path[77];
	getMsgPath(path, pubkey);

	const int fdMsg = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW, S_IRUSR | S_IWUSR | S_ISVTX);
	if (fdMsg < 0) {syslog(LOG_ERR, "Failed opening file %s", path); return -1;}

	const off_t oldFilesize = lseek(fdMsg, 0, SEEK_END);
	if (oldFilesize < 0) {syslog(LOG_ERR, "Failed lseek: %m"); return -1;}

	// Encrypt & Write
	unsigned char aesKey[32];
	getStorageKey(aesKey, pubkey, sze);
	struct AES_ctx aes;
	AES_init_ctx(&aes, aesKey);
	sodium_memzero(aesKey, 32);

	for (int i = 0; i < sze + AEM_MSG_MINBLOCKS; i++)
		AES_ECB_encrypt(&aes, data + i * 16);

	sodium_memzero(&aes, sizeof(struct AES_ctx));

	if (write(fdMsg, data, (sze + AEM_MSG_MINBLOCKS) * 16) != (sze + AEM_MSG_MINBLOCKS) * 16) {close(fdMsg); syslog(LOG_ERR, "Failed writing file %s", path); return -1;}

	// Stindex
	int num = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memcmp(pubkey, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) {
			num = i;
			break;
		}
	}

	if (num == -1) {
		stindexCount++;
		struct aem_stindex *stindex2 = realloc(stindex, sizeof(struct aem_stindex) * stindexCount);
		if (stindex2 == NULL) {
			ftruncate(fdMsg, oldFilesize);
			close(fdMsg);
			syslog(LOG_ERR, "Failed allocation");
			return -1;
		}
		stindex = stindex2;

		num = stindexCount - 1;
		memcpy(stindex[num].pubkey, pubkey, crypto_box_PUBLICKEYBYTES);
		stindex[num].msgCount = 0;
		stindex[num].msg = malloc(2);
		if (stindex[num].msg == NULL) {
			ftruncate(fdMsg, oldFilesize);
			close(fdMsg);
			syslog(LOG_ERR, "Failed allocation");
			return -1;
		}
	} else {
		uint16_t * const newMsg = realloc(stindex[num].msg, (stindex[num].msgCount + 1) * 2);
		if (newMsg == NULL) {
			ftruncate(fdMsg, oldFilesize);
			close(fdMsg);
			syslog(LOG_ERR, "Failed allocation");
			return -1;
		}
		stindex[num].msg = newMsg;
	}

	close(fdMsg);
	stindex[num].msg[stindex[num].msgCount] = sze;
	stindex[num].msgCount++;
	return 0;
}

static int storage_delete(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const unsigned char * const id) {
	int stindexNum = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memcmp(pubkey, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) {
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

	for (int i = stindex[stindexNum].msgCount - 1; i >= 0; i--) {
		filePos -= (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;

		if (!storage_idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, id)) continue;

		// ID matches
		if (i < stindex[stindexNum].msgCount - 1) {
			// Messages to preserve after this one
			const off_t readPos = filePos + (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;

			const ssize_t readAmount = fileSize - readPos;
			unsigned char * const buf = malloc(readAmount);
			if (buf == NULL) {close(fdMsg); return -1;}

			const ssize_t readBytes = pread(fdMsg, buf, readAmount, readPos);
			if (readBytes != readAmount) {close(fdMsg); free(buf); return -1;}

			pwrite(fdMsg, buf, readAmount, filePos);
			free(buf);
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
	return 0;
}

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
		memcpy(stindex[i].pubkey, data + skip, crypto_box_PUBLICKEYBYTES);
		skip += crypto_box_PUBLICKEYBYTES;

		memcpy(&(stindex[i].msgCount), data + skip, 2);
		skip += 2;

		stindex[i].msg = malloc(stindex[i].msgCount * 2);
		if (stindex[i].msg == NULL) return -1; // TODO: Free stindex

		for (int j = 0; j < stindex[i].msgCount; j++) {
			memcpy((unsigned char*)stindex[i].msg + (j * 2), data + skip, 2);
			skip += 2;
		}
	}

	return 0;
}

static void freeStindex(void) {
	for (int i = 0; i < stindexCount; i++) {
		sodium_memzero(stindex[i].msg, stindex[i].msgCount * 2);
		free(stindex[i].msg);
	}

	sodium_memzero(stindex, stindexCount * sizeof(struct aem_stindex));
	free(stindex);
}

static int bindSocket(const int sock) {
	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, AEM_SOCKPATH_STORAGE, AEM_SOCKPATH_LEN);
	return bind(sock, (struct sockaddr*)&addr, sizeof(addr.sun_family) + AEM_SOCKPATH_LEN);
}

static bool peerOk(const int sock) {
	struct ucred peer;
	unsigned int lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;
	return (peer.gid == getgid() && peer.uid == getuid());
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

static int storage_read(unsigned char * const msgData, const int stindexNum, const unsigned char * const matchId) {
	bzero(msgData, AEM_MAXLEN_MSGDATA);
	browse_infoBytes(msgData, stindexNum);

	char path[77];
	getMsgPath(path, stindex[stindexNum].pubkey);

	const int fdMsg = open(path, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fdMsg < 0) return fdMsg;

	off_t filePos = lseek(fdMsg, 0, SEEK_END);

	int startIndex = stindex[stindexNum].msgCount - 1;
	int stopIndex = -1;

	if (matchId != NULL) {
		if (matchId[0] & AEM_FLAG_NEWER) {
			for (int i = stindex[stindexNum].msgCount - 1; i >= 0; i--) {
				filePos -= (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;

				if (storage_idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, matchId + 1)) {
					stopIndex = i;
					break;
				}
			}

			if (stopIndex == -1) {close(fdMsg); return -1;} // matchId not found
			filePos = lseek(fdMsg, 0, SEEK_END);
		} else { // older
			filePos = lseek(fdMsg, 0, SEEK_SET); // TODO: check for error

			for (int i = 0; i < stindex[stindexNum].msgCount - 1; i++) {
				if (storage_idMatch(fdMsg, stindexNum, stindex[stindexNum].msg[i], filePos, matchId + 1)) {
					startIndex = i;
					filePos += (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;
					break;
				}

				filePos += (stindex[stindexNum].msg[i] + AEM_MSG_MINBLOCKS) * 16;
			}

			if (startIndex == 0 || startIndex == stindex[stindexNum].msgCount - 1) {close(fdMsg); return -1;} // matchId not found, or is the oldest
		}
	}

	int offset = 6; // browse_infoBytes

	for (int i = startIndex; i > stopIndex; i--) {
		const uint16_t sze = stindex[stindexNum].msg[i];
		if (offset + 2 + ((sze + AEM_MSG_MINBLOCKS) * 16) > AEM_MAXLEN_MSGDATA) break;

		memcpy(msgData + offset, &sze, 2);
		offset += 2;

		filePos -= (sze + AEM_MSG_MINBLOCKS) * 16;
		if (pread(fdMsg, msgData + offset, (sze + AEM_MSG_MINBLOCKS) * 16, filePos) != (sze + AEM_MSG_MINBLOCKS) * 16) {
			syslog(LOG_ERR, "Failed read (%d)", sze);
			break;
		}

		unsigned char aesKey[32];
		getStorageKey(aesKey, stindex[stindexNum].pubkey, stindex[stindexNum].msg[i]);
		struct AES_ctx aes;
		AES_init_ctx(&aes, aesKey);
		sodium_memzero(aesKey, 32);

		for (int j = 0; j < (sze + AEM_MSG_MINBLOCKS); j++)
			AES_ECB_decrypt(&aes, msgData + offset + (j * 16));

		sodium_memzero(&aes, sizeof(struct AES_ctx));

		offset += (sze + AEM_MSG_MINBLOCKS) * 16;
	}

	close(fdMsg);
	return offset;
}

static void takeConnections(void) {
	umask(0077);

	const int sockListen = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bindSocket(sockListen) != 0) return;
	listen(sockListen, AEM_SOCK_QUEUE);

	while (!terminate) {
		const int sock = accept4(sockListen, NULL, NULL, SOCK_CLOEXEC);
		if (sock < 0) continue;

		if (!peerOk(sock)) {
			syslog(LOG_WARNING, "Connection rejected from invalid user");
			close(sock);
			continue;
		}

		unsigned char enc[crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 64];
		const ssize_t lenEnc = recv(sock, enc, crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 64, 0);
		if (lenEnc < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 1) {close(sock); continue;}
		const size_t lenClr = lenEnc - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;

		unsigned char clr[lenClr];
		if (crypto_secretbox_open_easy(clr, enc + crypto_secretbox_NONCEBYTES, lenEnc - crypto_secretbox_NONCEBYTES, enc, AEM_KEY_ACCESS_STORAGE_API) == 0) {
			switch (clr[0]) {
				case AEM_API_MESSAGE_DELETE: {
					unsigned char ids[8192];
					const ssize_t lenIds = recv(sock, ids, 8192, 0);
					if (lenIds % 16 == 0) {
						for (int i = 0; i < lenIds / 16; i++) {
							storage_delete(clr + 1, ids + i * 16);
						}
					} else syslog(LOG_ERR, "Invalid data received");
				break;}

				case AEM_API_MESSAGE_UPLOAD: {
					uint16_t sze;
					memcpy(&sze, clr + 1, 2);

					unsigned char * const data = malloc((sze + AEM_MSG_MINBLOCKS) * 16);
					if (data == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}

					if (recv(sock, data, (sze + AEM_MSG_MINBLOCKS) * 16, MSG_WAITALL) == (sze + AEM_MSG_MINBLOCKS) * 16) {
						storage_write(clr + 3, data, sze);
						saveStindex();
					} else syslog(LOG_ERR, "Failed receiving data from API");

					free(data);
				break;}

				case AEM_API_MESSAGE_BROWSE: {
					if (lenClr != 1 + crypto_box_PUBLICKEYBYTES && lenClr != 1 + crypto_box_PUBLICKEYBYTES + 17) {syslog(LOG_ERR, "Message/Browse: Wrong length: %ld", lenClr); break;}

					int stindexNum = -1;
					for (int i = 0; i < stindexCount; i++) {
						if (memcmp(stindex[i].pubkey, clr + 1, crypto_box_PUBLICKEYBYTES) == 0) {
							stindexNum = i;
							break;
						}
					}

					if (stindexNum < 0) {
						// Stindex for account doesn't exist (new account, no messages received yet)
						if (send(sock, "\0", 1, 0) != 1) syslog(LOG_ERR, "Failed send");
						close(sock);
						continue;
					}

					unsigned char *msgData = sodium_malloc(AEM_MAXLEN_MSGDATA);
					const int sz = storage_read(msgData, stindexNum, (lenClr == 1 + crypto_box_PUBLICKEYBYTES + 17) ? clr + 1 + crypto_box_PUBLICKEYBYTES : NULL);
					if (sz > 0 && send(sock, msgData, sz, 0) != sz) syslog(LOG_ERR, "Failed send");
					sodium_free(msgData);
				break;}

				default: syslog(LOG_ERR, "Invalid API command");
			}
		} else if (crypto_secretbox_open_easy(clr, enc + crypto_secretbox_NONCEBYTES, lenEnc - crypto_secretbox_NONCEBYTES, enc, AEM_KEY_ACCESS_STORAGE_MTA) == 0) {
			if (clr[0] == AEM_MTA_INSERT) {
				uint16_t sze;
				while(1) {
					if (recv(sock, &sze, 2, MSG_WAITALL) != 2) {syslog(LOG_ERR, "MTA unclean end"); break;}
					if (sze == 0) break;

					unsigned char * const data = malloc((sze + AEM_MSG_MINBLOCKS) * 16);
					if (data == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}

					if (recv(sock, data, (sze + AEM_MSG_MINBLOCKS) * 16, MSG_WAITALL) == (sze + AEM_MSG_MINBLOCKS) * 16) {
						storage_write(clr + 1, data, sze);
						saveStindex();
					} else syslog(LOG_ERR, "Failed receiving data from MTA");

					free(data);
				}
			} else syslog(LOG_ERR, "Invalid MTA command");
		}

		close(sock);
	}

	close(sockListen);
}

__attribute__((warn_unused_result))
static int pipeLoad(const int fd) {
	return (read(fd, storageKey, AEM_LEN_KEY_STO) == AEM_LEN_KEY_STO) ? 0 : -1;
}

int main(int argc, char *argv[]) {
#include "../Common/MainSetup.c"

	if (
	   setCaps(CAP_IPC_LOCK) != 0
	|| mlockall(MCL_CURRENT | MCL_FUTURE) != 0
	) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	if (pipeLoad(argv[0][0]) < 0) {syslog(LOG_ERR, "Terminating: Failed loading data"); return EXIT_FAILURE;}
	close(argv[0][0]);
	crypto_kdf_derive_from_key(stindexKey, AEM_LEN_KEY_STI, 1, "AEM-Sti0", storageKey);

	if (loadStindex() != 0) {syslog(LOG_ERR, "Terminating: Failed opening Stindex.aem"); return EXIT_FAILURE;}

	syslog(LOG_INFO, "Ready");
	takeConnections();
	syslog(LOG_INFO, "Terminating");
	freeStindex();
	return EXIT_SUCCESS;
}
