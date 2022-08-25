#include <locale.h> // for setlocale
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> // for mlockall
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/IntCom_Client.h"
#include "../Common/IntCom_Server.h"
#include "../Common/SetCaps.h"
#include "IO.h"

#define AEM_LOGNAME "AEM-Acc"

static void sigTerm(const int sig) {
	if (sig == SIGUSR1) {
		tc_term();
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	ioFree();
	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"

static int setupIo(void) {
	pid_t storagePid;
	unsigned char accountKey[AEM_LEN_KEY_ACC];
	unsigned char saltShield[AEM_LEN_SLT_SHD];

	if (
	   read(AEM_FD_PIPE_RD, &storagePid, sizeof(pid_t)) != sizeof(pid_t)
	|| read(AEM_FD_PIPE_RD, accountKey, AEM_LEN_KEY_ACC) != AEM_LEN_KEY_ACC
	|| read(AEM_FD_PIPE_RD, saltShield, AEM_LEN_SLT_SHD) != AEM_LEN_SLT_SHD
	) {
		sodium_memzero(saltShield, AEM_LEN_SLT_SHD);
		close(AEM_FD_PIPE_RD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe");
		return -1;
	}

	close(AEM_FD_PIPE_RD);
	setStoragePid(storagePid);
	if (ioSetup(accountKey, saltShield) != 0) {syslog(LOG_ERR, "Terminating: Failed setting up IO"); return -1;}
	sodium_memzero(accountKey, AEM_LEN_KEY_ACC);
	sodium_memzero(saltShield, AEM_LEN_SLT_SHD);
	return 0;
}

int main(void) {
#include "../Common/MainSetup.c"
	umask(0077);

	if (
	   setCaps(CAP_IPC_LOCK) != 0
	|| mlockall(MCL_CURRENT | MCL_FUTURE) != 0
	) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	sleep(1);
	if (setupIo() != 0) return EXIT_FAILURE;
	syslog(LOG_INFO, "Ready");
	takeConnections();

	ioFree();
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
