#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sodium.h>

#include "../Global.h"

#define AEM_BLOCKSIZE 1024
#define AEM_SOCK_QUEUE 50

#define AEM_PATH_STINDEX "Stindex.aem"
#define AEM_PATH_STORAGE "Storage.aem"

static unsigned char accessKey_api[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_mta[AEM_LEN_ACCESSKEY];

static unsigned char stindexKey[AEM_LEN_KEY_STI];
static unsigned char storageKey[AEM_LEN_KEY_STO];

struct aem_stindex {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	uint16_t msgCount;
	uint32_t *msg;
};

static struct aem_stindex *stindex;
static uint16_t stindexCount;

static uint32_t *empty;

static int fdMsg;

static bool terminate = false;

static void sigTerm(const int sig) {
	if (sig != SIGUSR2) {
		terminate = true;
		syslog(LOG_MAIL | LOG_NOTICE, "Terminating after next connection");
		return;
	}

	sodium_memzero(stindexKey, 32);
	sodium_memzero(storageKey, 32);

	syslog(LOG_MAIL | LOG_NOTICE, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

static int storage_write(const unsigned char pubkey[crypto_box_PUBLICKEYBYTES], const unsigned char *data, int size) {
	if (size < 1 || size > 128) return -1;

	// TODO: Check emptyBlocks

	const off_t pos = lseek(fdMsg, 0, SEEK_END);
	if (pos == (off_t)-1 || pos % 1024 != 0) return -1;
	if (pos > (33554431L * AEM_BLOCKSIZE)) return -1; // 25-bit limit

	// TODO: Encrypt data with Storage Key

	if (write(fdMsg, data, size * AEM_BLOCKSIZE) != size * AEM_BLOCKSIZE) return -1;

	int num = -1;
	for (int i = 0; i < stindexCount; i++) {
		if (memcmp(pubkey, stindex[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) {
			num = i;
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
		uint32_t *newMsg = realloc(stindex[num].msg, (stindex[num].msgCount + 1) * 4);
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

static int saveStindex(void) {
	if (stindexCount <= 0) return -1;

	size_t lenClear = 2;
	for (int i = 0; i < stindexCount; i++) {
		lenClear += (crypto_box_PUBLICKEYBYTES + 2 + (4 * stindex[i].msgCount));
	}

	unsigned char clear[lenClear];
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

	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear;
	unsigned char * const encrypted = malloc(lenEncrypted);
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, clear, lenClear, encrypted, stindexKey);

	const int fd = open(AEM_PATH_STINDEX, O_WRONLY | O_TRUNC);
	if (fd < 0) {free(encrypted); return -1;}
	const ssize_t ret = write(fd, encrypted, lenEncrypted);
	close(fd);
	free(encrypted);

	return (ret == (ssize_t)lenEncrypted) ? 0 : -1;
}

int loadStindex() {
	const int fd = open(AEM_PATH_STINDEX, O_RDONLY);
	if (fd < 0) return -1;

	const off_t sz = lseek(fd, 0, SEEK_END);
	if (sz == 0) {
		stindexCount = 0;
		stindex = malloc(1);
		close(fd);
		return 0;
	}

	unsigned char *encd = malloc(sz);
	if (pread(fd, encd, sz, 0) != sz) {close(fd); return -1;}
	close(fd);

	unsigned char data[sz];
	if (crypto_secretbox_open_easy(data, encd + crypto_secretbox_NONCEBYTES, sz - crypto_secretbox_NONCEBYTES, encd, stindexKey) != 0) {free(encd); return -1;}
	free(encd);

	memcpy(&stindexCount, data, 2);
	size_t skip = 2;

	stindex = malloc(sizeof(struct aem_stindex) * stindexCount);
	for (int i = 0; i < stindexCount; i++) {
		memcpy(stindex[i].pubkey, data + skip, crypto_box_PUBLICKEYBYTES);
		skip += crypto_box_PUBLICKEYBYTES;

		memcpy(&(stindex[i].msgCount), data + skip, 2);
		skip += 2;

		stindex[i].msg = malloc(stindex[i].msgCount * 4);
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

	sodium_memzero(stindex, stindexCount * sizeof(stindex));
	free(stindex);
}

static int bindSocket(const int sock) {
	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "Storage.sck");
	unlink(addr.sun_path);
	const int lenAddr = strlen(addr.sun_path) + sizeof(addr.sun_family);

	return bind(sock, (struct sockaddr*)&addr, lenAddr);
}

void takeConnections(void) {
	int sockListen = socket(AF_UNIX, SOCK_STREAM, 0);
	if (bindSocket(sockListen) != 0) return;
	listen(sockListen, AEM_SOCK_QUEUE);

	while (!terminate) {
		const int sock = accept(sockListen, NULL, NULL);

		const size_t lenClr = 1 + crypto_box_PUBLICKEYBYTES;
		const size_t lenEnc = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClr;
		unsigned char enc[lenEnc];
		if (recv(sock, enc, lenEnc, 0) != lenEnc) {
			close(sock);
			continue;
		}

		unsigned char clr[lenClr];
		if (crypto_secretbox_open_easy(clr, enc + crypto_secretbox_NONCEBYTES, lenEnc - crypto_secretbox_NONCEBYTES, enc, accessKey_api) == 0) {
			const int rfd = open("Message.aem", O_RDONLY);

			for (int i = 0; i < stindex[0].msgCount; i++) {
				const ssize_t len = ((stindex[0].msg[i] & 127) + 1) * AEM_BLOCKSIZE;
				const size_t pos = (stindex[0].msg[i] >> 7) * AEM_BLOCKSIZE;

				unsigned char buf[len];
				if (pread(rfd, buf, len, pos) != len) {syslog(LOG_MAIL | LOG_NOTICE, "Failed read"); close(rfd); break;}
				if (send(sock, buf, len, 0) != len) {syslog(LOG_MAIL | LOG_NOTICE, "Failed send"); close(rfd); break;}
				recv(sock, buf, 1, 0);
			}

			close(rfd);
		} else if (crypto_secretbox_open_easy(clr, enc + crypto_secretbox_NONCEBYTES, lenEnc - crypto_secretbox_NONCEBYTES, enc, accessKey_mta) == 0) {
			const ssize_t bytes = clr[0] * AEM_BLOCKSIZE;
			unsigned char * const msg = malloc(bytes);
			if (msg == NULL) break;

			if (recv(sock, msg, bytes, 0) == bytes) {
				storage_write(clr + 1, msg, clr[0]);
				saveStindex();
			} else syslog(LOG_MAIL | LOG_NOTICE, "Failed to receive data from MTA");
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

__attribute__((warn_unused_result))
static int setSignals(void) {
	return (
	   signal(SIGPIPE, SIG_IGN) != SIG_ERR

	&& signal(SIGINT,  sigTerm) != SIG_ERR
	&& signal(SIGQUIT, sigTerm) != SIG_ERR
	&& signal(SIGTERM, sigTerm) != SIG_ERR
	&& signal(SIGUSR1, sigTerm) != SIG_ERR
	&& signal(SIGUSR2, sigTerm) != SIG_ERR
	) ? 0 : -1;
}

int main(int argc, char *argv[]) {
	if (argc > 1 || argv == NULL) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Invalid arguments"); return EXIT_FAILURE;}
	if (getuid()      == 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Must not be started as root"); return EXIT_FAILURE;}
	if (setSignals()  != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed setting up signal handling"); return EXIT_FAILURE;}
	if (sodium_init()  < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed initializing libsodium"); return EXIT_FAILURE;}

	if (pipeLoad(argv[0][0]) < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed loading data"); return EXIT_FAILURE;}
	close(argv[0][0]);

	if (loadStindex() != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed opening Stindex.aem"); return EXIT_FAILURE;}
	if ((fdMsg = open("Message.aem", O_RDWR)) < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed opening Message.aem"); return EXIT_FAILURE;}

	syslog(LOG_MAIL | LOG_NOTICE, "Ready");
	takeConnections();
	syslog(LOG_MAIL | LOG_NOTICE, "Terminating");
	freeStindex();
	return EXIT_SUCCESS;
}
