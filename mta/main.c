#include <arpa/inet.h>
#include <locale.h> // for setlocale
#include <net/if.h>
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

#include <sodium.h>

#include "delivery.h"
#include "smtp.h"

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/SetCaps.h"
#include "../Common/UnixSocketClient.h"
#include "../Common/ValidIp.h"

#define AEM_LOGNAME "AEM-MTA"
#define AEM_PIPEFD 2
#define AEM_MAXLEN_PIPEREAD 8192
#define AEM_MINLEN_PIPEREAD 128

static bool terminate = false;

static void sigTerm(const int sig) {
	terminate = true;

	if (sig == SIGUSR1) {
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	// SIGUSR2: Fast kill
	delSignKey_mta();
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

	if (read(AEM_PIPEFD, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_KEY_SIG) return -1;
	setSignKey_mta(buf);

	sodium_memzero(buf, AEM_MAXLEN_PIPEREAD);
	return 0;
}

static void acceptClients(void) {
	const int sock = createSocket(AEM_PORT_MTA, false, 10, 10);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (setCaps(0) != 0) return;

	syslog(LOG_INFO, "Ready");

	struct sockaddr_in clientAddr;
	unsigned int clen = sizeof(clientAddr);

	while (!terminate) {
		const int newSock = accept4(sock, (struct sockaddr*)&clientAddr, &clen, SOCK_CLOEXEC);
		if (newSock < 0) continue;
		if (validIp(clientAddr.sin_addr.s_addr)) respondClient(newSock, &clientAddr);
		close(newSock);
	}

	close(sock);
}

int main(void) {
#include "../Common/MainSetup.c"
	if (pipeLoadPids() < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids: %m"); return EXIT_FAILURE;}
	if (pipeLoadKeys() < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears keys: %m"); return EXIT_FAILURE;}
	close(AEM_PIPEFD);

	tlsSetup();
	acceptClients();

	delSignKey_mta();
	tlsFree();
	return EXIT_SUCCESS;
}
