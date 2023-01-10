#include <syslog.h>
#include <strings.h> // for bzero
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/IntCom_KeyBundle.h"
#include "../Common/IntCom_Client.h"
#include "../Common/IntCom_Server.h"
#include "IO.h"

#define AEM_LOGNAME "AEM-Acc"

#include "../Common/Main_Include.c"

static int setupIo(void) {
	pid_t storagePid;
	unsigned char baseKey[crypto_kdf_KEYBYTES];
	struct intcom_keyBundle bundle;

	if (
	   read(AEM_FD_PIPE_RD, &storagePid, sizeof(pid_t)) != sizeof(pid_t)
	|| read(AEM_FD_PIPE_RD, baseKey, crypto_kdf_KEYBYTES) != crypto_kdf_KEYBYTES
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
	) {
		close(AEM_FD_PIPE_RD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe");
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	setStoragePid(storagePid);
	intcom_setKeys_server(bundle.server);
	intcom_setKeys_client(bundle.client);
	if (ioSetup(baseKey) != 0) {syslog(LOG_ERR, "Terminating: Failed setting up IO"); return -1;}

	sodium_memzero(baseKey, crypto_kdf_KEYBYTES);
	sodium_memzero(&bundle, sizeof(bundle));
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
