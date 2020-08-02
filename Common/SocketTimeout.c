#include <sys/socket.h>

#include "SocketTimeout.h"

int setSocketTimeout(const int sock, const time_t rcvSec, const time_t sndSec) {
	struct timeval tv;
	tv.tv_usec = 1; // 0 tv_sec means almost-instant timeout

	tv.tv_sec = rcvSec;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) != 0) return -1;

	tv.tv_sec = sndSec;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) != 0) return -1;

	return 0;
}
