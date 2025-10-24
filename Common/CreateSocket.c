#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#ifdef AEM_UDS
#include <sys/un.h>
#endif
#include <syslog.h>
#include <unistd.h>

#include "../Config.h"
#include "../Common/memeq.h"

#include "CreateSocket.h"

#ifdef AEM_UDS
static char udsId = -1;

void setUdsId(char newId) {
	udsId = newId;
}

__attribute__((warn_unused_result))
int createSocket(void) {
	if (udsId == -1) return -1;

	const int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_ERR, "socket failed: %m"); return -1;}

	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, AEM_UDS_PATH_API, AEM_UDS_PATH_API_LEN);

	if (bind(sock, (struct sockaddr*)&sa, sizeof(sa.sun_family) + AEM_UDS_PATH_API_LEN) != 0) {syslog(LOG_ERR, "bind failed: %m"); close(sock); return -1;}
	if (listen(sock, AEM_BACKLOG) != 0) {syslog(LOG_ERR, "listen failed: %m"); close(sock); return -1;}

	return sock;
}
#else
static int setSocketTimeout(const int sock, const time_t rcvSec, const time_t sndSec) {
	struct timeval tv;
	tv.tv_usec = 1; // 0 tv_sec means almost-instant timeout

	tv.tv_sec = rcvSec;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) != 0) return -1;

	tv.tv_sec = sndSec;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) != 0) return -1;

	return 0;
}

__attribute__((warn_unused_result))
int createSocket(const bool loopback, const time_t rcvTimeout, const time_t sndTimeout) {
	const int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) return -1;

	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(AEM_PORT);

	const int intTrue = 1;
#ifndef AEM_MANAGER
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,   (const void*)&intTrue, sizeof(int)) != 0) {close(sock); return -1;}
#endif
	if (setsockopt(sock, SOL_SOCKET, SO_LOCK_FILTER, (const void*)&intTrue, sizeof(int)) != 0) {close(sock); return -1;}

	if (loopback) {
		servAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) != 0) {close(sock); return -1;}
		if (setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, (const void*)&intTrue, sizeof(int)) != 0) {close(sock); return -1;}
	} else {
		servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		struct if_nameindex * const ni = if_nameindex();
		for (int i = 0;; i++) {
			if (ni[i].if_index == 0) {if_freenameindex(ni); close(sock); return -1;}
			if (memeq(ni[i].if_name, "lo", 2)) continue;
			if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ni[i].if_name, strlen(ni[i].if_name) + 1) != 0) {if_freenameindex(ni); close(sock); return -1;}
			break;
		}
		if_freenameindex(ni);
	}

	if (
	   setSocketTimeout(sock, rcvTimeout, sndTimeout) == 0
	&& bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) == 0
	&& listen(sock, AEM_BACKLOG) == 0
	) return sock;

	close(sock);
	return -1;
}
#endif
