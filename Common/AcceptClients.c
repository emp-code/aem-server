#include <signal.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#ifdef AEM_MTA
#include <netinet/in.h>
#endif

#include "CreateSocket.h"
#include "SetCaps.h"

#ifdef AEM_MTA
#include "ValidIp.h"
#endif

#if defined(AEM_API)
	#include "../api/respond.h"
#elif defined(AEM_MTA)
	#include "../mta/respond.h"
#elif defined(AEM_WEB_CLR)
	#include "../web-clr/respond.h"
#elif defined(AEM_WEB_ONI)
	#include "../web-oni/respond.h"
#endif

#include "AcceptClients.h"

#include "../Config.h" // for AEM_PORT

#define AEM_FD_SOCK_MAIN 0
// syslog 1
#define AEM_FD_SOCK_CLIENT 2

static volatile sig_atomic_t terminate = 0;
void sigTerm() {
	terminate = 1;
	close(AEM_FD_SOCK_MAIN);
	close(AEM_FD_SOCK_CLIENT);
}

void acceptClients(void) {
	if (createSocket(
#ifdef AEM_IS_ONION
	true,
#else
	false,
#endif
	10, 10) != AEM_FD_SOCK_MAIN) {syslog(LOG_ERR, "Failed creating socket"); return;}

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
		if (newSock != AEM_FD_SOCK_CLIENT) {close(AEM_FD_SOCK_MAIN); break;}

#ifdef AEM_MTA
		if (validIp(clientAddr.sin_addr.s_addr)) respondClient(newSock, &clientAddr);
#else
		respondClient(newSock);
#endif

		close(newSock);
	}
}
