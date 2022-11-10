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

#include "../Global.h"
#include "../Common/IntCom_Client.h"
#include "../Common/IntCom_Server.h"
#include "../Common/SetCaps.h"

#define AEM_LOGNAME "AEM-DLV"
#define AEM_MAXLEN_PIPEREAD 64

static bool terminate = false;

static void sigTerm(const int sig) {
	terminate = true;

	if (sig == SIGUSR1) {
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	// SIGUSR2: Fast kill
	delSignKey();
	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"

__attribute__((warn_unused_result))
static int pipeLoadPids(void) {
	pid_t pid;
	if (read(AEM_FD_PIPE_RD, &pid, sizeof(pid_t)) != sizeof(pid_t)) return -1;
	setStoragePid(pid);
	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadKeys(void) {
	unsigned char buf[AEM_MAXLEN_PIPEREAD];

	if (read(AEM_FD_PIPE_RD, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_KEY_SIG) return -1;
	setSignKey(buf);

	sodium_memzero(buf, AEM_MAXLEN_PIPEREAD);
	return 0;
}

int main(void) {
#include "../Common/MainSetup.c"
	if (pipeLoadPids() != 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids: %m"); return EXIT_FAILURE;}
	if (pipeLoadKeys() != 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears keys: %m"); return EXIT_FAILURE;}
	close(AEM_FD_PIPE_RD);

	takeConnections();

	delSignKey();
	return EXIT_SUCCESS;
}
