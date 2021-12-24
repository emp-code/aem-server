#include <locale.h> // for setlocale
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> // for mlockall
#include <sys/mount.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/SetCaps.h"

#include "IntCom_Server.h"
#include "IO.h"

#define AEM_LOGNAME "AEM-Sto"
#define AEM_PIPEFD 1

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
	unsigned char storageKey[AEM_LEN_KEY_STO];
	if (read(AEM_PIPEFD, storageKey, AEM_LEN_KEY_STO) != AEM_LEN_KEY_STO) {
		close(AEM_PIPEFD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe: %m");
		return -1;
	}

	close(AEM_PIPEFD);
	ioSetup(storageKey);
	sodium_memzero(storageKey, AEM_LEN_KEY_STO);
	return 0;
}

int main(void) {
#include "../Common/MainSetup.c"
	umask(0077);

	if (
	   setCaps(CAP_IPC_LOCK) != 0
	|| mlockall(MCL_CURRENT | MCL_FUTURE) != 0
	) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	if (setupIo() != 0) return EXIT_FAILURE;
	syslog(LOG_INFO, "Ready");
	takeConnections();

	ioFree();
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
