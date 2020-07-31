#include <arpa/inet.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"

#define AEM_LOGNAME "AEM-WOn"
#define AEM_BACKLOG 25

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

static int initSocket(void) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	servAddr.sin_port = htons(AEM_PORT_WEB_ONI);

	const int intTrue = 1;
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	return (sock > 0
	&& setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) == 0
	&& setsockopt(sock, SOL_SOCKET, SO_DONTROUTE,   (const void*)&intTrue, sizeof(int)) == 0
	&& setsockopt(sock, SOL_SOCKET, SO_LOCK_FILTER, (const void*)&intTrue, sizeof(int)) == 0
	&& bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) == 0
	&& listen(sock, AEM_BACKLOG) == 0
	) ? sock : -1;
}

static void acceptClients(void) {
	if (html == NULL || lenHtml < 1) return;

	const int sock = initSocket();
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}

	syslog(LOG_INFO, "Ready");

	while(1) {
		const int sockClient = accept4(sock, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
		if (sockClient < 0) continue;

		shutdown(sockClient, SHUT_RD);
		write(sockClient, html, lenHtml);
		close(sockClient);
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
