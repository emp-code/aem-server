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

#include <sodium.h>

#define AEM_BLOCKSIZE 1024
#define AEM_SOCK_QUEUE 50

struct aem_block {
	uint32_t location; // Block number. 1 KiB blocks --> 4 TiB max
	uint8_t size; // Number of blocks.
};

struct aem_message {
	uint16_t userNum;
	struct aem_block block;
};

static struct aem_message *msg;
static unsigned int msgCount;

static struct aem_block *emptyBlocks;

static unsigned char storageKey[32];
static unsigned char accessKey_api[crypto_secretbox_KEYBYTES];
static unsigned char accessKey_mta[crypto_secretbox_KEYBYTES];

static bool terminate = false;

static void sigTerm(const int sig) {
	if (sig != SIGUSR2) {
		terminate = true;
		syslog(LOG_MAIL | LOG_NOTICE, "Terminating after next connection");
		return;
	}

	sodium_memzero(storageKey, 32);

	syslog(LOG_MAIL | LOG_NOTICE, "Terminating immediately");
	exit(EXIT_SUCCESS);
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

	char cmd_buf[5];
	while (!terminate) {
		const int sock = accept(sockListen, NULL, NULL);

		if (recv(sock, cmd_buf, 5, 0) != 5) {
			close(sock);
			continue;
		}

		switch (cmd_buf[0]) {
//			case 'D': delete(); break;
//			case 'R': read(); break;
//			case 'W': write(); break;
		}

		explicit_bzero(cmd_buf, 5);
		close(sock);
	}

	close(sockListen);
}

__attribute__((warn_unused_result))
static int pipeLoad(const int fd) {
	return (
	   read(fd, storageKey, 32) == 32
	&& read(fd, accessKey_api, crypto_secretbox_KEYBYTES) == crypto_secretbox_KEYBYTES
	&& read(fd, accessKey_mta, crypto_secretbox_KEYBYTES) == crypto_secretbox_KEYBYTES
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

	syslog(LOG_MAIL | LOG_NOTICE, "Ready");
	takeConnections();
	syslog(LOG_MAIL | LOG_NOTICE, "Terminating");
	return EXIT_SUCCESS;
}
