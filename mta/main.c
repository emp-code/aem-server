#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "respond.h"

#include "../Global.h"
#include "../Common/AcceptClients.h"
#include "../IntCom/Client.h"
#include "../IntCom/Stream_Client.h"

#define AEM_LOGNAME "AEM-MTA"

#include "../Common/Main_Include.c"

__attribute__((warn_unused_result))
static int pipeRead(void) {
	pid_t pids[2];
	struct intcom_keyBundle bundle;

	if (
	   read(AEM_FD_PIPE_RD, &pids, sizeof(pid_t) * 2) != sizeof(pid_t) * 2
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
	) {
		close(AEM_FD_PIPE_RD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe");
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	setAccountPid(pids[0]);
	intcom_setPid_stream(pids[1]);

	intcom_setKeys_client(bundle.client);
	intcom_setKey_stream(bundle.stream);

	sodium_memzero(&bundle, sizeof(bundle));
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeRead() != 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids: %m"); return EXIT_FAILURE;}

	tlsSetup();
	acceptClients();

	syslog(LOG_INFO, "Terminating");
	tlsFree();
	return EXIT_SUCCESS;
}
