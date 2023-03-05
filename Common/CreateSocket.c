#include <arpa/inet.h>
#include <net/if.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#include "../Config.h"
#include "../Common/memeq.h"

#include "CreateSocket.h"

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

	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(AEM_PORT);

	const int intTrue = 1;
#ifndef AEM_MANAGER
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,   (const void*)&intTrue, sizeof(int)) != 0) return -1;
#endif
	if (setsockopt(sock, SOL_SOCKET, SO_LOCK_FILTER, (const void*)&intTrue, sizeof(int)) != 0) return -1;

	if (loopback) {
		servAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) != 0) return -1;
		if (setsockopt(sock, SOL_SOCKET, SO_DONTROUTE, (const void*)&intTrue, sizeof(int)) != 0) return -1;
	} else {
		servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		struct if_nameindex * const ni = if_nameindex();
		for (int i = 0;; i++) {
			if (ni[i].if_index == 0) {if_freenameindex(ni); return -1;}
			if (memeq(ni[i].if_name, "lo", 2)) continue;
			if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ni[i].if_name, strlen(ni[i].if_name) + 1) != 0) {if_freenameindex(ni); return -1;}
			break;
		}
		if_freenameindex(ni);
	}

	return (
	   setSocketTimeout(sock, rcvTimeout, sndTimeout) == 0
	&& bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) == 0
	&& listen(sock, AEM_BACKLOG) == 0
	) ? sock : -1;
}
