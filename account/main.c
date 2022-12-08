#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/IntCom_Client.h"
#include "../Common/IntCom_Server.h"
#include "IO.h"

#define AEM_LOGNAME "AEM-Acc"

#include "../Common/Main_Include.c"

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
#include "../Common/Main_Setup.c"

	sleep(1);
	if (setupIo() != 0) return EXIT_FAILURE;

	syslog(LOG_INFO, "Ready");
	takeConnections();

	syslog(LOG_INFO, "Terminating");
	ioFree();
	return EXIT_SUCCESS;
}
