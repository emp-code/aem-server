#include <signal.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#ifdef AEM_MTA
	#include <netinet/in.h>
#endif

#ifdef AEM_API_CLR
	#include "../api/ClientTLS.h"
#endif

#include "../Config.h" // for AEM_PORT
#include "../Common/CreateSocket.h"
#include "../Common/SetCaps.h"
#ifdef AEM_MTA
	#include "../Common/ValidIp.h"
#endif

#if defined(AEM_API)
	#include "../api/Request.h"
#elif defined(AEM_MTA)
	#include "../mta/respond.h"
#endif

#include "../Global.h"

#include "AcceptClients.h"

static volatile sig_atomic_t terminate = 0;
void sigTerm(const int s) {
	terminate = 1;
}

void acceptClients(void) {
	if (createSocket(
#ifdef AEM_LOCAL
	true,
#else
	false,
#endif
	10, 10) != AEM_FD_SOCK_MAIN) {syslog(LOG_ERR, "Failed creating socket: %m"); return;}

	if (setCaps(0) != 0) return;

	syslog(LOG_INFO, "Ready");

#ifdef AEM_MTA
	struct sockaddr_in clientAddr;
	unsigned int clen = sizeof(clientAddr);
#endif

	while (terminate == 0) {
		const int newSock = accept4(AEM_FD_SOCK_MAIN, 
#ifdef AEM_MTA
			(struct sockaddr*)&clientAddr, &clen
#else
			NULL, NULL
#endif
			, SOCK_CLOEXEC);

		if (newSock < 0) continue;
		if (newSock != AEM_FD_SOCK_CLIENT) {close(newSock); break;}

#ifdef AEM_MTA
		if (validIp(clientAddr.sin_addr.s_addr)) respondClient(newSock, &clientAddr);
#elifdef AEM_API_CLR
		if (tls_connect() == 0) {
			if (!respondClient()) shutdown(newSock, SHUT_RDWR);
			tls_disconnect();
		}
#else
		respondClient();
#endif

		close(AEM_FD_SOCK_CLIENT);
	}

	close(AEM_FD_SOCK_MAIN);
}
