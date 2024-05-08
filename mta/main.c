#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../Common/AcceptClients.h"
#include "../IntCom/Client.h"
#include "../IntCom/Stream_Client.h"

#include "respond.h"

#define AEM_LOGNAME "AEM-MTA"

#include "../Common/Main_Include.c"

__attribute__((warn_unused_result))
static int pipeRead(void) {
	pid_t pids[2];
	struct intcom_keyBundle bundle;

	size_t lenTlsCrt;
	size_t lenTlsKey;
	unsigned char tlsCrt[PIPE_BUF];
	unsigned char tlsKey[PIPE_BUF];

	if (
	   read(AEM_FD_PIPE_RD, &pids, sizeof(pid_t) * 2) != sizeof(pid_t) * 2
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
	|| read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsCrt, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsCrt, lenTlsCrt) != lenTlsCrt
	|| read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsKey, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsKey, lenTlsKey) != lenTlsKey
	) {
		syslog(LOG_ERR, "Failed reading pipe: %m");
		close(AEM_FD_PIPE_RD);
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	setAccountPid(pids[0]);
	intcom_setPid_stream(pids[1]);

	intcom_setKeys_client(bundle.client);
	intcom_setKey_stream(bundle.stream);
	sodium_memzero(&bundle, sizeof(bundle));

	tlsSetup(tlsCrt, lenTlsCrt, tlsKey, lenTlsKey);
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeRead() != 0) {syslog(LOG_ERR, "Terminating: failed pipeRead"); return EXIT_FAILURE;}

	acceptClients();

	syslog(LOG_INFO, "Terminating");
	tlsFree();
	return EXIT_SUCCESS;
}
