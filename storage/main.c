#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../IntCom/Client.h"
#include "../IntCom/Server.h"

#include "IO.h"

#define AEM_LOGNAME "AEM-Sto"

#include "../Common/Main_Include.c"

static int setupIo(void) {
	unsigned char baseKey[AEM_KDF_SUB_KEYLEN];
	struct intcom_keyBundle bundle;

	if (
	   read(AEM_FD_PIPE_RD, baseKey, AEM_KDF_SUB_KEYLEN) != AEM_KDF_SUB_KEYLEN
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
	) {
		close(AEM_FD_PIPE_RD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe: %m");
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	if (ioSetup(baseKey) != 0) {
		sodium_memzero(baseKey, AEM_KDF_SUB_KEYLEN);
		sodium_memzero(&bundle, sizeof(bundle));
		return -1;
	}

	intcom_setKeys_server(bundle.server);
	intcom_setKeys_client(bundle.client);

	sodium_memzero(baseKey, AEM_KDF_SUB_KEYLEN);
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
