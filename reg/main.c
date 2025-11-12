#include <syslog.h>
#include <unistd.h>

#include "../Common/AcceptClients.h"
#include "../Common/CreateSocket.h"
#include "../IntCom/Client.h"

#define AEM_LOGNAME "AEM-Reg"

#include "respond.h"

#include "../Common/Main_Include.c"

__attribute__((warn_unused_result))
static int pipeRead(void) {
	pid_t accPid;
	struct intcom_keyBundle bundle;

	if (
	   read(AEM_FD_PIPE_RD, &accPid, sizeof(pid_t)) != sizeof(pid_t)
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
	) {
		syslog(LOG_ERR, "Failed reading pipe: %m");
		close(AEM_FD_PIPE_RD);
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	setAccountPid(accPid);

	intcom_setKeys_client(bundle.client);
	sodium_memzero(&bundle, sizeof(bundle));

	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeRead() < 0) {syslog(LOG_ERR, "Terminating: Failed pipeRead"); return EXIT_FAILURE;}
	setUdsId(0);
	acceptClients();

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
