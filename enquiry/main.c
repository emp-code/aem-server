#include <syslog.h>
#include <unistd.h>

#include "../IntCom/Server.h"

#define AEM_LOGNAME "AEM-Enq"

#define AEM_PIPE_NOLARGE
#include "../Common/Main_Include.c"
#include "../Common/PipeRead.c"

static int pipeLoad(void) {
	struct intcom_keyBundle bundle;

	if (
	   pipeReadSmall(&bundle, sizeof(bundle)) != 0
	) {close(AEM_FD_PIPE_RD); return -1;}
	close(AEM_FD_PIPE_RD);

	intcom_setKeys_server(bundle.server);

	sodium_memzero(&bundle, sizeof(bundle));
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeLoad() != 0) return EXIT_FAILURE;

	syslog(LOG_INFO, "Ready");
	intcom_serve();

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
