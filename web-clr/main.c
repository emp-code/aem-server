#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "https.h"

#include "../Global.h"
#include "../Common/CreateSocket.h"

#define AEM_LOGNAME "AEM-Web"

#include "../Common/Main_Include.c"

static void acceptClients(void) {
	const int sock = createSocket(AEM_PORT_WEB, false, 10, 10);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (setCaps(0) != 0) return;

	syslog(LOG_INFO, "Ready");

	while(1) {
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (newSock < 0) continue;
		respondClient(newSock);
		close(newSock);
	}

	close(sock);
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (tlsSetup() != 0) return EXIT_FAILURE;

	acceptClients();

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
