#include <fcntl.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h> // for mlockall
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "aes.h"

#include "../Global.h"
#include "../Common/SetCaps.h"

#define AEM_LOGNAME "AEM-Sto"
#define AEM_BLOCKSIZE 1024
#define AEM_STINDEX_PAD 1048576 // 1 MiB
#define AEM_SOCK_QUEUE 50

static unsigned char accessKey_api[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_mta[AEM_LEN_ACCESSKEY];

static unsigned char stindexKey[AEM_LEN_KEY_STI];
static unsigned char storageKey[AEM_LEN_KEY_STO];

struct aem_stindex {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	uint16_t msgCount;
	uint32_t *msg; // (& 127) + 1: size; >> 7: position
};

static struct aem_stindex *stindex;
static uint16_t stindexCount;

static uint32_t *empty;
static int emptyCount;

static int fdMsg;

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

static int saveStindex(void) {
	if (stindexCount < 1) return -1;

	size_t lenClear = 2;
	for (int i = 0; i < stindexCount; i++) {
		lenClear += (crypto_box_PUBLICKEYBYTES + 2 + (4 * stindex[i].msgCount));
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

		memcpy(clear + skip, stindex[i].msg, 4 * stindex[i].msgCount);
		skip += (4 * stindex[i].msgCount);
	}

	const ssize_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear + lenPad;
	unsigned char * const encrypted = malloc(lenEncrypted);
	if (encrypted == NULL) {syslog(LOG_ERR, "Failed allocation"); free(clear); return -1;}

	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear + lenPad, encrypted, stindexKey);

	sodium_memzero(clear, lenClear);
	free(clear);

	const int fd = open("Stindex.aem", O_WRONLY | O_TRUNC | O_NOCTTY | O_CLOEXEC | O_NOATIME | O_NOFOLLOW);
	if (fd < 0) {free(encrypted); return -1;}
	const ssize_t ret = write(fd, encrypted, lenEncrypted);
	close(fd);
	free(encrypted);

	return (ret == lenEncrypted) ? 0 : -1;
}

static int getWritePos(const int size) {
	for (int i = 0; i < emptyCount; i++) {
		int emptySze = empty[i] & 127;
		if (emptySze < size - 1) continue; // Empty slot too small

		int emptyPos = empty[i] >> 7;
		const int pos = emptyPos * AEM_BLOCKSIZE;

		if (emptySze == size - 1) { // Exact match, use and remove this empty slot
			memmove((unsigned char*)empty + i * 4, (unsigned char*)empty + 4 * (i + 1), 4 * (emptyCount - i - 1));
			emptyCount--;
		} else { // Use part of, and adjust this empty slot
			emptySze -= size;
			emptyPos += size;

			empty[i] = (emptyPos << 7) | emptySze;
		}

		return pos;
	}

	// No suitable empty slot found - append to end
	const off_t pos = lseek(fdMsg, 0, SEEK_END);
	if (pos == (off_t)-1 || pos % 1024 != 0) return -1;
	if (pos > (33554431L * AEM_BLOCKSIZE)) return -1; // 25-bit limit
	return pos;
}

static int storage_write(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], unsigned char * const data, const int size) {
	if (size < 1 || size > 128) return -1;

	const int pos = getWritePos(size);
	if (pos < 0) return -1;

	// Encrypt & Write
	struct AES_ctx aes;
	AES_init_ctx(&aes, storageKey);

	for (int i = 0; i < (size * AEM_BLOCKSIZE) / 16; i++)
		AES_ECB_encrypt(&aes, data + i * 16);

	sodium_memzero(&aes, sizeof(struct AES_ctx));
	if (pwrite(fdMsg, data, size * AEM_BLOCKSIZE, pos) != size * AEM_BLOCKSIZE) return -1;

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
			// TODO
			return -1;
		}
		stindex = stindex2;

		num = stindexCount - 1;
		memcpy(stindex[num].pubkey, pubkey, crypto_box_PUBLICKEYBYTES);
		stindex[num].msgCount = 0;
		stindex[num].msg = malloc(4);
	} else {
		uint32_t * const newMsg = realloc(stindex[num].msg, (stindex[num].msgCount + 1) * 4);
		if (newMsg == NULL) {
			// TODO
			return -1;
		}
		stindex[num].msg = newMsg;
	}

	const int msgNum = stindex[num].msgCount;
	stindex[num].msg[msgNum] = ((pos / 1024) << 7) | (size - 1);
	stindex[num].msgCount++;

	return 0;
}

static bool storage_idMatch(const int stindexNum, const int i, const unsigned char * const id) {
	unsigned char buf[AEM_BLOCKSIZE];
	const ssize_t readBytes = pread(fdMsg, buf, AEM_BLOCKSIZE, (stindex[stindexNum].msg[i] >> 7) * AEM_BLOCKSIZE);
	if (readBytes != AEM_BLOCKSIZE) {
		syslog(LOG_ERR, "Failed reading Storage.aem");
		return false;
	}

	struct AES_ctx aes;
	AES_init_ctx(&aes, storageKey);

	for (int j = 0; j < AEM_BLOCKSIZE / 16; j++)
		AES_ECB_decrypt(&aes, buf + j * 16);

	for (int j = 0; j < 16; j++) {
		if (id[j] != buf[j * 64]) return false;
	}

	return true;
}

static int storage_delete(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const unsigned char * const id) {
	int num = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memcmp(pubkey, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) {
			num = i;
			break;
		}
	}

	if (num == -1) {syslog(LOG_NOTICE, "Invalid pubkey in delete request"); return -1;}

	for (int i = 0; i < stindex[num].msgCount; i++) {
		if (storage_idMatch(num, i, id)) {
			uint32_t * const empty2 = realloc(empty, 4 * (emptyCount + 1));
			if (empty2 != NULL) {
				empty = empty2;
				empty[emptyCount] = stindex[num].msg[i];
				emptyCount++;
			}

			const int pos = (stindex[num].msg[i] >> 7) * AEM_BLOCKSIZE;
			const int sze = ((stindex[num].msg[i] & 127) + 1) * AEM_BLOCKSIZE;

			memmove((unsigned char*)stindex[num].msg + i * 4, (unsigned char*)stindex[num].msg + 4 * (i + 1), 4 * (stindex[num].msgCount - i - 1));
			stindex[num].msgCount--;
			saveStindex();

			unsigned char zero[sze];
			bzero(zero, sze);
			pwrite(fdMsg, zero, sze, pos);
		}
	}

	return 0;
}

int loadStindex() {
	const int fd = open("Stindex.aem", O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NOATIME | O_NOFOLLOW);
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

		stindex[i].msg = malloc(stindex[i].msgCount * 4);
		if (stindex[i].msg == NULL) return -1; // TODO: Free stindex

		for (int j = 0; j < stindex[i].msgCount; j++) {
			memcpy((unsigned char*)stindex[i].msg + (j * 4), data + skip, 4);
			skip += 4;
		}
	}

	return 0;
}

void freeStindex(void) {
	for (int i = 0; i < stindexCount; i++) {
		sodium_memzero(stindex[i].msg, stindex[i].msgCount * 4);
		free(stindex[i].msg);
	}

	sodium_memzero(stindex, stindexCount * sizeof(struct aem_stindex));
	free(stindex);
}

static int loadEmpty(void) {
	const off_t total = lseek(fdMsg, 0, SEEK_END);
	if (total % AEM_BLOCKSIZE != 0) return -1;

	empty = malloc(1);
	if (empty == NULL) return -1;
	emptyCount = 0;

	int blocks = 0;
	int pos = -1;

	for (int i = 0; i < (total / AEM_BLOCKSIZE); i++) {
		unsigned char buf[AEM_BLOCKSIZE];
		if (pread(fdMsg, buf, AEM_BLOCKSIZE, i * AEM_BLOCKSIZE) != AEM_BLOCKSIZE) {
			syslog(LOG_ERR, "Failed read");
			free(empty);
			return -1;
		}

		bool isEmpty = true;
		for (int j = 0; j < AEM_BLOCKSIZE; j++) {
			if (buf[j] != 0) {isEmpty = false; break;}
		}

		if (isEmpty) {
			// TODO handle >128 blocks

			if (pos == -1) pos = i;

			blocks++;
		} else if (blocks > 0) {
			uint32_t * const empty2 = realloc(empty, (emptyCount + 1) * 4);
			if (empty2 == NULL) {free(empty); return -1;}
			empty = empty2;

			empty[emptyCount] = pos << 7 | (blocks - 1);

			blocks = 0;
			pos = -1;
			emptyCount++;
		}
	}

	return 0;
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

static void browse_infoBytes(const int stindexNum, unsigned char * const target) {
	const uint16_t count = stindex[stindexNum].msgCount;

	uint32_t kilos = 0;
	for (int i = 0; i < stindex[stindexNum].msgCount; i++) {
		kilos += (stindex[stindexNum].msg[i] & 127) + 1;
	}

	memcpy(target, &count, 2);
	memcpy(target + 2, &kilos, 3);
}

void takeConnections(void) {
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

		const size_t lenClr = 1 + crypto_box_PUBLICKEYBYTES;
		const size_t lenEnc = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClr;
		unsigned char enc[lenEnc];
		if (recv(sock, enc, lenEnc, 0) != lenEnc) {
			close(sock);
			continue;
		}

		unsigned char clr[lenClr];
		if (crypto_secretbox_open_easy(clr, enc + crypto_secretbox_NONCEBYTES, lenEnc - crypto_secretbox_NONCEBYTES, enc, accessKey_api) == 0) {
			if (clr[0] == 0) { // Delete
				unsigned char ids[8192];
				const ssize_t lenIds = recv(sock, ids, 8192, 0);
				if (lenIds % 16 == 0) {
					for (int i = 0; i < lenIds / 16; i++) {
						storage_delete(clr + 1, ids + i * 16);
					}
				} else syslog(LOG_ERR, "Invalid data received");
			} else if (clr[0] <= 8) { // Store
				const ssize_t bytes = clr[0] * AEM_BLOCKSIZE;
				unsigned char * const msg = malloc(bytes);
				if (msg == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}

				if (recv(sock, msg, bytes, MSG_WAITALL) == bytes) {
					storage_write(clr + 1, msg, clr[0]);
					saveStindex();
				} else syslog(LOG_ERR, "Failed receiving data from API");

				free(msg);
			} else if (clr[0] == UINT8_MAX) { // Browse
				int stindexNum = -1;
				for (int i = 0; i < stindexCount; i++) {
					if (memcmp(stindex[i].pubkey, clr + 1, crypto_box_PUBLICKEYBYTES) == 0) {
						stindexNum = i;
						break;
					}
				}

				if (stindexNum < 0) {
					close(sock);
					continue;
				}

				unsigned char startAfterId[16];
				if (recv(sock, startAfterId, 16, 0) != 16) {
					close(sock);
					continue;
				}

				int startIndex = stindex[stindexNum].msgCount - 1;
				if (memcmp(startAfterId, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) != 0) {
					for (int i = startIndex; i >= 0; i--) {
						if (storage_idMatch(stindexNum, i, startAfterId)) {
							startIndex = i - 1;
							break;
						}
					}
				}

				unsigned char msgData[131205]; // 128 bytes + 128 KiB + 5 bytes
				bzero(msgData, 131205);

				browse_infoBytes(stindexNum, msgData + sizeof(msgData) - 5);

				int msgNum = 0;
				int msgKib = 0;

				for (int i = startIndex; i >= 0; i--) {
					const int kib = (stindex[stindexNum].msg[i] & 127) + 1;
					if (msgKib + kib > 128) break;

					const ssize_t len = kib * AEM_BLOCKSIZE;
					const size_t pos = (stindex[stindexNum].msg[i] >> 7) * AEM_BLOCKSIZE;

					const size_t msgPos = 128 + (msgKib * 1024);

					if (pread(fdMsg, msgData + msgPos, len, pos) != len) {
						syslog(LOG_ERR, "Failed read");
						break;
					}

					struct AES_ctx aes;
					AES_init_ctx(&aes, storageKey);

					for (int j = 0; j < (kib * AEM_BLOCKSIZE) / 16; j++)
						AES_ECB_decrypt(&aes, msgData + msgPos + (j * 16));

					msgData[msgNum] = kib;

					msgKib += kib;
					msgNum++;
					if (msgNum > 127) break;
				}

				if (send(sock, msgData, 131205, 0) != 131205) {syslog(LOG_ERR, "Failed send"); break;}
			}
		} else if (crypto_secretbox_open_easy(clr, enc + crypto_secretbox_NONCEBYTES, lenEnc - crypto_secretbox_NONCEBYTES, enc, accessKey_mta) == 0) {
			const ssize_t bytes = clr[0] * AEM_BLOCKSIZE;
			unsigned char * const msg = malloc(bytes);
			if (msg == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}

			if (recv(sock, msg, bytes, MSG_WAITALL) == bytes) {
				storage_write(clr + 1, msg, clr[0]);
				saveStindex();
			} else syslog(LOG_ERR, "Failed receiving data from MTA");

			free(msg);
		}

		close(sock);
	}

	close(sockListen);
}

__attribute__((warn_unused_result))
static int pipeLoad(const int fd) {
	return (
	   read(fd, stindexKey, AEM_LEN_KEY_STI) == AEM_LEN_KEY_STI
	&& read(fd, storageKey, AEM_LEN_KEY_STO) == AEM_LEN_KEY_STO
	&& read(fd, accessKey_api, AEM_LEN_ACCESSKEY) == AEM_LEN_ACCESSKEY
	&& read(fd, accessKey_mta, AEM_LEN_ACCESSKEY) == AEM_LEN_ACCESSKEY
	) ? 0 : -1;
}

int main(int argc, char *argv[]) {
#include "../Common/MainSetup.c"

	if (
	   setCaps(CAP_IPC_LOCK) != 0
	|| mlockall(MCL_CURRENT | MCL_FUTURE) != 0
	) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	if (pipeLoad(argv[0][0]) < 0) {syslog(LOG_ERR, "Terminating: Failed loading data"); return EXIT_FAILURE;}
	close(argv[0][0]);

	fdMsg = open("Storage.aem", O_RDWR | O_NOCTTY | O_CLOEXEC | O_NOATIME | O_NOFOLLOW);
	if (fdMsg < 0) {syslog(LOG_ERR, "Terminating: Failed opening Storage.aem"); return EXIT_FAILURE;}
	if (loadStindex() != 0) {syslog(LOG_ERR, "Terminating: Failed opening Stindex.aem"); return EXIT_FAILURE;}
	if (loadEmpty() != 0) {syslog(LOG_ERR, "Terminating: Failed loading Storage.aem"); return EXIT_FAILURE;}

	syslog(LOG_INFO, "Ready");
	takeConnections();
	syslog(LOG_INFO, "Terminating");
	freeStindex();
	free(empty);
	return EXIT_SUCCESS;
}
