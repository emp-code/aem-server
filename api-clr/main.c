#include <arpa/inet.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <mbedtls/ssl.h>
#include <sodium.h>

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/SetCaps.h"

#include "https.h"
#include "../api-common/post.h"

#define AEM_LOGNAME "AEM-API"
#define AEM_PIPEFD 2
#define AEM_MAXLEN_PIPEREAD 64

static bool terminate = false;

static void sigTerm(const int sig) {
	terminate = true;

	if (sig == SIGUSR1) {
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	// SIGUSR2: Fast kill
	aem_api_free();
	tlsFree();
	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"

__attribute__((warn_unused_result))
static int pipeLoadPids(void) {
	pid_t pids[3];
	if (read(AEM_PIPEFD, pids, sizeof(pid_t) * 3) != sizeof(pid_t) * 3) return -1;

	setAccountPid(pids[0]);
	setStoragePid(pids[1]);
	setEnquiryPid(pids[2]);
	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadKeys(void) {
	unsigned char buf[AEM_MAXLEN_PIPEREAD];

	if (read(AEM_PIPEFD, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_KEY_API) return -1;
	setApiKey(buf);

	if (read(AEM_PIPEFD, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_KEY_SIG) return -1;
	setSigKey(buf);

	sodium_memzero(buf, AEM_MAXLEN_PIPEREAD);
	return 0;
}

static void acceptClients(void) {
	const int sock = createSocket(AEM_PORT_API, false, 10, 10);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (setCaps(0) != 0) return;

	syslog(LOG_INFO, "Ready");

	while (!terminate) {
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (newSock < 0) continue;
		respondClient(newSock);
		close(newSock);
	}

	close(sock);
}

int main(void) {
#include "../Common/MainSetup.c"
	if (pipeLoadPids() < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids: %m"); return EXIT_FAILURE;}
	if (pipeLoadKeys() < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears keys: %m"); return EXIT_FAILURE;}
	close(AEM_PIPEFD);

	if (tlsSetup() != 0) {syslog(LOG_ERR, "Terminating: Failed initializing TLS"); return EXIT_FAILURE;}
	if (aem_api_init() != 0) {syslog(LOG_ERR, "Terminating: Failed initializing API"); return EXIT_FAILURE;}

	acceptClients();

	aem_api_free();
	tlsFree();

	return EXIT_SUCCESS;
}
