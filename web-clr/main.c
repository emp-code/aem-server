#include <arpa/inet.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "https.h"

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/SetCaps.h"

#define AEM_LOGNAME "AEM-Web"

static void sigTerm(const int sig) {
	syslog(LOG_INFO, "Terminating");
	tlsFree();
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"

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
#include "../Common/MainSetup.c"

	if (tlsSetup() != 0) return EXIT_FAILURE;

	acceptClients();

	return EXIT_SUCCESS;
}
