#include <signal.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/SetCaps.h"

#define AEM_LOGNAME "AEM-Web"

size_t lenResp;
unsigned char *resp;

static volatile sig_atomic_t terminate = 0;
static void sigTerm(const int s) {terminate = 1;}

#include "../Common/Main_Include.c"

static void acceptClients(void) {
	const int sock = createSocket(true, 10, 10);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (setCaps(0) != 0) return;

	syslog(LOG_INFO, "Ready");

	while (terminate == 0) {
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (newSock < 0) continue;

		shutdown(newSock, SHUT_RD);
		write(newSock, resp, lenResp);
		close(newSock);
	}

	close(sock);
}

static int pipeRead(void) {
	if (read(AEM_FD_PIPE_RD, (unsigned char*)&lenResp, sizeof(size_t)) != sizeof(size_t)) {syslog(LOG_ERR, "Failed reading from pipe: %m"); return -1;}
	if (lenResp < 1 || lenResp > 99999) return -2;

	resp = malloc(lenResp);
	if (resp == NULL) return -3;

	size_t tbr = lenResp;
	while (tbr > 0) {
		if (tbr > PIPE_BUF) {
			if (read(AEM_FD_PIPE_RD, resp + (lenResp - tbr), PIPE_BUF) != PIPE_BUF) return -4;
			tbr -= PIPE_BUF;
		} else {
			if (read(AEM_FD_PIPE_RD, resp + (lenResp - tbr), tbr) != (ssize_t)tbr) return -4;
			break;
		}
	}

	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"
	const int pr = pipeRead();
	close(AEM_FD_PIPE_RD);
	if (pr != 0) {
		syslog(LOG_ERR, "pipeRead failed: %d", pr);
	} else {
		acceptClients();
	}

	syslog(LOG_INFO, "Terminating");
	return 0;
}
