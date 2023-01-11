#include <syslog.h>
#include <unistd.h>

#include "../IntCom/Server.h"

#include "../Global.h"

#include "IO.h"

#define AEM_LOGNAME "AEM-Sto"

#include "../Common/Main_Include.c"

static int setupIo(void) {
	unsigned char baseKey[crypto_kdf_KEYBYTES];
	struct intcom_keyBundle bundle;

	if (
	   read(AEM_FD_PIPE_RD, baseKey, crypto_kdf_KEYBYTES) != crypto_kdf_KEYBYTES
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
	) {
		close(AEM_FD_PIPE_RD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe: %m");
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	ioSetup(baseKey);
	intcom_setKeys_server(bundle.server);

	sodium_memzero(baseKey, crypto_kdf_KEYBYTES);
	sodium_memzero(&bundle, sizeof(bundle));
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (setupIo() != 0) return EXIT_FAILURE;

	syslog(LOG_INFO, "Ready");
	takeConnections();

	ioFree();
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
