#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../IntCom/Client.h"
#include "../IntCom/Server.h"

#include "IO.h"

#define AEM_LOGNAME "AEM-Sto"

#include "../Common/Main_Include.c"

static int setupIo(void) {
	unsigned char baseKey[AEM_KDF_KEYSIZE];
	struct intcom_keyBundle bundle;

	if (
	   read(AEM_FD_PIPE_RD, baseKey, AEM_KDF_KEYSIZE) != AEM_KDF_KEYSIZE
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
	) {
		close(AEM_FD_PIPE_RD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe: %m");
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	ioSetup(baseKey);
	intcom_setKeys_server(bundle.server);
	intcom_setKeys_client(bundle.client);

	sodium_memzero(baseKey, AEM_KDF_KEYSIZE);
	sodium_memzero(&bundle, sizeof(bundle));
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (setupIo() != 0) return EXIT_FAILURE;

	syslog(LOG_INFO, "Ready");
	intcom_serve();

	ioFree();
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
