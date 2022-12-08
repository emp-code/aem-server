#include <arpa/inet.h>
#include <locale.h> // for setlocale
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h> // for mlockall
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h> // for umask
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "store.h"

#include "../Global.h"
#include "../Common/IntCom_Client.h"
#include "../Common/IntCom_Stream_Server.h"
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
	pid_t pids[2];
	if (read(AEM_FD_PIPE_RD, pids, sizeof(pid_t) * 2) != sizeof(pid_t) * 2) return -1;

	setEnquiryPid(pids[0]);
	setStoragePid(pids[1]);

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
	umask(0077);

	if (
	   setCaps(CAP_IPC_LOCK) != 0
	|| mlockall(MCL_CURRENT | MCL_FUTURE) != 0
	) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	if (pipeLoadPids() != 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids: %m"); return EXIT_FAILURE;}
	if (pipeLoadKeys() != 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears keys: %m"); return EXIT_FAILURE;}
	close(AEM_FD_PIPE_RD);

	syslog(LOG_INFO, "Ready");
	takeConnections();

	delSignKey();
	return EXIT_SUCCESS;
}
