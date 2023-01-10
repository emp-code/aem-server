#include <syslog.h>
#include <unistd.h>

#include "../IntCom/Server.h"

#define AEM_LOGNAME "AEM-Enq"

#include "../Common/Main_Include.c"

static int readKeys(void) {
	struct intcom_keyBundle bundle;

	if (read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)) {
		close(AEM_FD_PIPE_RD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe");
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	intcom_setKeys_server(bundle.server);

	sodium_memzero(&bundle, sizeof(bundle));
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (readKeys() != 0) return EXIT_FAILURE;

	syslog(LOG_INFO, "Ready");
	takeConnections();

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
