#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../IntCom/Client.h"
#include "../IntCom/Server.h"

#include "IO.h"

#define AEM_LOGNAME "AEM-Sto"

#define AEM_PIPE_NOLARGE
#include "../Common/Main_Include.c"
#include "../Common/PipeRead.c"

__attribute__((warn_unused_result))
static int pipeLoad(void) {
	unsigned char baseKey[AEM_KDF_SUB_KEYLEN];
	struct intcom_keyBundle bundle;

	if (
	   pipeReadSmall(baseKey, AEM_KDF_SUB_KEYLEN) != 0
	|| pipeReadSmall(&bundle, sizeof(bundle)) != 0
	) {close(AEM_FD_PIPE_RD); return -1;}
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

	if (pipeLoad() != 0) return EXIT_FAILURE;

	syslog(LOG_INFO, "Ready");
	intcom_serve();

	ioFree();
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
