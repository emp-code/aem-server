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

#include <sodium.h>

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/SetCaps.h"

#define AEM_LOGNAME "AEM-WOn"

#define AEM_MAXLEN_PIPEREAD 8192
#define AEM_MINLEN_PIPEREAD 128
#define AEM_WEB_ONI

unsigned char *html;
size_t lenHtml;

static void sigTerm(const int sig) {
	sodium_free(html);
	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"
#include "../Common/PipeLoad.c"

static void acceptClients(void) {
	const int sock = createSocket(AEM_PORT_WEB_ONI, true, 10, 10);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (setCaps(0) != 0) return;

	syslog(LOG_INFO, "Ready");

	while(1) {
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (newSock < 0) {syslog(LOG_ERR, "Failed creating socket"); continue;}

		shutdown(newSock, SHUT_RD);
		write(newSock, html, lenHtml);
		close(newSock);
	}

	close(sock);
}

static int setHtml(const unsigned char * const data, const size_t len) {
	html = sodium_malloc(len);
	if (html == NULL) return -1;

	memcpy(html, data, len);
	sodium_mprotect_readonly(html);
	lenHtml = len;
	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadHtml(const int fd) {
	unsigned char buf[AEM_MAXLEN_PIPEREAD];
	const off_t readBytes = pipeReadDirect(fd, buf, AEM_MAXLEN_PIPEREAD);
	if (readBytes < AEM_MINLEN_PIPEREAD) return -1;
	return setHtml(buf, readBytes);
}

int main(int argc, char *argv[]) {
#include "../Common/MainSetup.c"
	if (pipeLoadHtml(argv[0][0]) < 0) {syslog(LOG_ERR, "Terminating: Failed loading HTML"); return EXIT_FAILURE;}
	close(argv[0][0]);

	acceptClients();

	sodium_free(html);
	return EXIT_SUCCESS;
}
