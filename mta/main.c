#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "smtp.h"

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/IntCom_Client.h"
#include "../Common/IntCom_Stream_Client.h"
#include "../Common/ValidIp.h"

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

static void acceptClients(void) {
	const int sock = createSocket(AEM_PORT_MTA, false, 10, 10);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (setCaps(0) != 0) return;

	syslog(LOG_INFO, "Ready");

	struct sockaddr_in clientAddr;
	unsigned int clen = sizeof(clientAddr);

	while (!terminate) {
		const int newSock = accept4(sock, (struct sockaddr*)&clientAddr, &clen, SOCK_CLOEXEC);
		if (newSock < 0) continue;
		if (validIp(clientAddr.sin_addr.s_addr)) respondClient(newSock, &clientAddr);
		close(newSock);
	}

	close(sock);
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeRead() != 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids: %m"); return EXIT_FAILURE;}
	close(AEM_FD_PIPE_RD);

	tlsSetup();
	acceptClients();

	syslog(LOG_INFO, "Terminating");
	tlsFree();
	return EXIT_SUCCESS;
}
