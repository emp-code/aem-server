#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../IntCom/Client.h"
#include "../IntCom/Stream_Server.h"

#include "format.h"

#define AEM_LOGNAME "AEM-DLV"

#define AEM_PIPE_NOLARGE
#include "../Common/Main_Include.c"
#include "../Common/PipeRead.c"

__attribute__((warn_unused_result))
static int pipeLoad(void) {
	pid_t pids[2];
	struct intcom_keyBundle bundle;

	if (
	   pipeReadSmall(pids, sizeof(pid_t) * 2) != 0
	|| pipeReadSmall(&bundle, sizeof(bundle)) != 0
	) {close(AEM_FD_PIPE_RD); return -1;}
	close(AEM_FD_PIPE_RD);

	setEnquiryPid(pids[0]);
	setStoragePid(pids[1]);

	intcom_setKeys_client(bundle.client);
	intcom_setKey_stream(bundle.stream);

	sodium_memzero(&bundle, sizeof(struct intcom_keyBundle));
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeLoad() != 0) return EXIT_FAILURE;

	syslog(LOG_INFO, "Ready");
	intcom_serve_stream();

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
