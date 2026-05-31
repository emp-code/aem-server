#include <syslog.h>
#include <unistd.h>

#include "../Common/AcceptClients.h"
#include "../Common/CreateSocket.h"
#include "../IntCom/Client.h"

#define AEM_LOGNAME "AEM-Reg"

#include "respond.h"

#define AEM_PIPE_NOLARGE
#include "../Common/Main_Include.c"
#include "../Common/PipeRead.c"

__attribute__((warn_unused_result))
static int pipeLoad(void) {
	pid_t accPid;
	struct intcom_keyBundle bundle;

	if (
	   pipeReadSmall(&accPid, sizeof(pid_t)) != 0
	|| pipeReadSmall(&bundle, sizeof(bundle)) != 0
	) {close(AEM_FD_PIPE_RD); return -1;}
	close(AEM_FD_PIPE_RD);

	setAccountPid(accPid);

	intcom_setKeys_client(bundle.client);
	sodium_memzero(&bundle, sizeof(bundle));

	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeLoad() < 0) return EXIT_FAILURE;
	acceptClients();

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
