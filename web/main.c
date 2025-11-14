#include <signal.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/SetCaps.h"
#include "../Common/x509_getCn.h"

#define AEM_LOGNAME "AEM-Web"

static volatile sig_atomic_t terminate = 0;
static void sigTerm(const int s) {terminate = 1;}

#include "../Common/Main_Include.c"

size_t lenResp;
unsigned char *resp;
static int lenSts;
static char sts[512];

static void acceptClients(void) {
	const int sock = createSocket();
	if (sock < 0) return;
	if (setCaps(0) != 0) return;

	syslog(LOG_INFO, "Ready");

	while (terminate == 0) {
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (newSock < 0) continue;

		unsigned char req[29];
		if (
		read(newSock, req, 29) == 29) {
			if (memcmp(req, "GET /.well-known/mta-sts.txt ", 29) == 0) {
				write(newSock, sts, lenSts);
			} else if (memcmp(req, "GET / HTTP/", 11) == 0) {
				write(newSock, resp, lenResp);
			} else {
				close(newSock);
				continue;
			}
		}

		shutdown(newSock, SHUT_RD);
		close(newSock);
	}

	close(sock);
}

static int pipeRead(void) {
	if (read(AEM_FD_PIPE_RD, (unsigned char*)&lenResp, sizeof(size_t)) != sizeof(size_t)) {syslog(LOG_ERR, "Failed reading from pipe: %m"); return 1;}
	if (lenResp < 1 || lenResp > 99999) return 2;

	resp = malloc(lenResp);
	if (resp == NULL) return 3;

	size_t tbr = lenResp;
	while (tbr > 0) {
		if (tbr > PIPE_BUF) {
			if (read(AEM_FD_PIPE_RD, resp + (lenResp - tbr), PIPE_BUF) != PIPE_BUF) return 4;
			tbr -= PIPE_BUF;
		} else {
			if (read(AEM_FD_PIPE_RD, resp + (lenResp - tbr), tbr) != (ssize_t)tbr) return 5;
			break;
		}
	}

	size_t lenTlsCrt;
	size_t lenTlsKey;
	unsigned char tlsCrt[PIPE_BUF];
	unsigned char tlsKey[PIPE_BUF];

	if (
	   read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsCrt, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsCrt, lenTlsCrt) != (ssize_t)lenTlsCrt
	|| read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsKey, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsKey, lenTlsKey) != (ssize_t)lenTlsKey
	) return 6;

	unsigned char cn[100];
	size_t lenCn;
	if (x509_getSubject(cn, &lenCn, tlsCrt, lenTlsCrt) != 0) return 12;

	lenSts = sprintf(sts,
		"HTTP/1.1 200 aem\r\n"
		"Cache-Control: public, max-age=9999999, immutable\r\n"
		"Connection: close\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Strict-Transport-Security: max-age=99999999; includeSubDomains; preload\r\n"
		"X-Robots-Tag: noindex\r\n"
		"\r\n"
		"version: STSv1\n"
		"mode: enforce\n"
		"max_age: 31557600\n"
		"mx: %.*s"
	, 51 + lenCn, (int)lenCn, (char*)cn);

	sodium_memzero(tlsCrt, lenTlsCrt);
	sodium_memzero(tlsKey, lenTlsKey);

	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"
	const int pr = pipeRead();
	if (pr != 0) {
		close(AEM_FD_PIPE_RD);
		syslog(LOG_INFO, "pipeRead failed: %d", pr);
		return 1;
	}

	close(AEM_FD_PIPE_RD);
	acceptClients();
	return 0;
}
