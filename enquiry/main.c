#include <locale.h> // for setlocale
#include <signal.h>
#include <sys/mman.h> // for mlockall
#include <sys/mount.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/IntCom_Server.h"
#include "../Common/SetCaps.h"

#define AEM_LOGNAME "AEM-Enq"

static void sigTerm(const int sig) {
	if (sig == SIGUSR1) {
		tc_term();
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"

int main(void) {
#include "../Common/MainSetup.c"
	umask(0077);

	if (
	   setCaps(CAP_IPC_LOCK) != 0
	|| mlockall(MCL_CURRENT | MCL_FUTURE) != 0
	) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	syslog(LOG_INFO, "Ready");
	takeConnections();
	syslog(LOG_INFO, "Terminating");

	return EXIT_SUCCESS;
}
