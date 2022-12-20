#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/SetCaps.h"
#include "../Data/html.h"

#define AEM_LOGNAME "AEM-WOn"

#include "../Common/Main_Include.c"

static void acceptClients(void) {
	const int sock = createSocket(AEM_PORT_WEB_ONI, true, 10, 10);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (setCaps(0) != 0) return;

	syslog(LOG_INFO, "Ready");

	while (!terminate) {
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (newSock < 0) continue;

		shutdown(newSock, SHUT_RD);
		write(newSock, AEM_HTML_ONI_DATA, AEM_HTML_ONI_SIZE);
		close(newSock);
	}

	close(sock);
}

int main(void) {
#include "../Common/Main_Setup.c"

	acceptClients();

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
