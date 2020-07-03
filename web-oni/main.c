#include <arpa/inet.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
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
#define AEM_WEBONION

unsigned char *html;
size_t lenHtml;

static void sigTerm(const int sig) {
	sodium_free(html);
	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"
#include "../Common/PipeLoad.c"

static int initSocket(const int * const sock) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	servAddr.sin_port = htons(80);

	const int ret = bind(*sock, (struct sockaddr*)&servAddr, sizeof(servAddr));
	if (ret < 0) return ret;

	listen(*sock, AEM_BACKLOG);
	return 0;
}

static void acceptClients(void) {
	if (html == NULL || lenHtml < 1) return;

	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {puts("ERROR: Opening socket failed"); return;}
	if (initSocket(&sock) < 0) {puts("ERROR: Binding socket failed"); return;}
	listen(sock, AEM_BACKLOG);

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
