#include <arpa/inet.h>
#include <locale.h> // for setlocale
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <mbedtls/ssl.h>
#include <sodium.h>

#include "https.h"

#include "../Global.h"
#include "../Common/SetCaps.h"

#define AEM_LOGNAME "AEM-Web"
#define AEM_PORT AEM_PORT_WEB
#define AEM_BACKLOG 25

#define AEM_MAXLEN_PIPEREAD 8192
#define AEM_MINLEN_PIPEREAD 128

#define AEM_SOCKET_TIMEOUT 15

static bool terminate = false;

static void sigTerm(const int sig) {
	terminate = true;

	if (sig == SIGUSR1) {
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	// SIGUSR2: Fast kill
	freeHtml();
	tlsFree();
	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"
#include "../Common/main_common.c"
#include "../Common/PipeLoad.c"

__attribute__((warn_unused_result))
static int pipeLoadHtml(const int fd) {
	unsigned char buf[AEM_MAXLEN_PIPEREAD];
	const off_t readBytes = pipeReadDirect(fd, buf, AEM_MAXLEN_PIPEREAD);
	if (readBytes < AEM_MINLEN_PIPEREAD) return -1;
	return setHtml(buf, readBytes);
}

int main(int argc, char *argv[]) {
#include "../Common/MainSetup.c"
	if (setCaps(CAP_NET_BIND_SERVICE, CAP_NET_RAW) != 0) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	if (pipeLoadTls(argv[0][0])  < 0) {syslog(LOG_ERR, "Terminating: Failed loading TLS cert/key"); return EXIT_FAILURE;}
	if (pipeLoadHtml(argv[0][0]) < 0) {syslog(LOG_ERR, "Terminating: Failed loading HTML"); return EXIT_FAILURE;}
	close(argv[0][0]);

	acceptClients();

	freeHtml();
	tlsFree();
	return EXIT_SUCCESS;
}
