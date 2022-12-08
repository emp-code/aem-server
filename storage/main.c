#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../Common/IntCom_Server.h"

#include "IO.h"

#define AEM_LOGNAME "AEM-Sto"

#include "../Common/Main_Include.c"

static int setupIo(void) {
	unsigned char storageKey[AEM_LEN_KEY_STO];
	if (read(AEM_FD_PIPE_RD, storageKey, AEM_LEN_KEY_STO) != AEM_LEN_KEY_STO) {
		close(AEM_FD_PIPE_RD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe: %m");
		return -1;
	}

	close(AEM_FD_PIPE_RD);
	ioSetup(storageKey);
	sodium_memzero(storageKey, AEM_LEN_KEY_STO);
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (setupIo() != 0) return EXIT_FAILURE;

	syslog(LOG_INFO, "Ready");
	takeConnections();

	syslog(LOG_INFO, "Terminating");
	ioFree();
	return EXIT_SUCCESS;
}
