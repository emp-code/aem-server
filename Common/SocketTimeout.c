#include <sys/socket.h>

#include "SocketTimeout.h"

void setSocketTimeout(const int sock, const time_t rcvSec, const time_t sndSec) {
	struct timeval tv;
	tv.tv_usec = 1; // 0 tv_sec means almost-instant timeout

	tv.tv_sec = rcvSec;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));

	tv.tv_sec = sndSec;
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval));
}
