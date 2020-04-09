#define _GNU_SOURCE // for accept4

#include <arpa/inet.h>
#include <locale.h> // for setlocale
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

#include "delivery.h"
#include "smtp.h"

#include "../Global.h"

#define AEM_LOGNAME "AEM-MTA"
#define AEM_MINLEN_PIPEREAD 128
#define AEM_PIPE_BUFSIZE 8192
#define AEM_SOCKET_TIMEOUT 30

static mbedtls_x509_crt tlsCrt;
static mbedtls_pk_context tlsKey;

static unsigned char *tls_crt;
static unsigned char *tls_key;
static size_t len_tls_crt;
static size_t len_tls_key;

static bool terminate = false;

static void sigTerm(const int sig) {
	terminate = true;

	if (sig == SIGUSR1) {
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	// SIGUSR2: Fast kill
	tlsFree();
	mbedtls_x509_crt_free(&tlsCrt);
	mbedtls_pk_free(&tlsKey);
	sodium_free(tls_crt);
	sodium_free(tls_key);
	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/SetSignals.c"
#include "../Common/main_common.c"
#include "../Common/PipeLoad.c"

__attribute__((warn_unused_result))
static int pipeLoadPids(const int fd) {
	pid_t pid;

	if (read(fd, &pid, sizeof(pid_t)) != sizeof(pid_t)) return -1;
	setAccountPid(pid);

	if (read(fd, &pid, sizeof(pid_t)) != sizeof(pid_t)) return -1;
	setStoragePid(pid);

	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadKeys(const int fd) {
	unsigned char buf[AEM_PIPE_BUFSIZE];

	if (read(fd, buf, AEM_PIPE_BUFSIZE) != AEM_LEN_ACCESSKEY) return -1;
	setAccessKey_account(buf);

	if (read(fd, buf, AEM_PIPE_BUFSIZE) != AEM_LEN_ACCESSKEY) return -1;
	setAccessKey_storage(buf);

	sodium_memzero(buf, AEM_PIPE_BUFSIZE);
	return 0;
}

static void takeConnections(void) {
	const int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {syslog(LOG_ERR, "Failed creating socket"); return;}
	if (initSocket(sock, AEM_PORT_MTA, 50) != 0) {syslog(LOG_ERR, "Failed initSocket"); close(sock); return;}
	if (tlsSetup(&tlsCrt, &tlsKey) != 0) {syslog(LOG_ERR, "Failed setting up TLS"); close(sock); return;}

	syslog(LOG_INFO, "Ready");

	struct sockaddr_in clientAddr;
	unsigned int clen = sizeof(clientAddr);

	while (!terminate) {
		const int newSock = accept4(sock, (struct sockaddr*)&clientAddr, &clen, SOCK_CLOEXEC);
		if (newSock < 0) {syslog(LOG_ERR, "Failed creating socket"); continue;}
		setSocketTimeout(newSock);
		respond_smtp(newSock, &clientAddr);
		close(newSock);
	}

	tlsFree();
	close(sock);
}

int main(int argc, char *argv[]) {
#include "../Common/MainSetup.c"
	if (setCaps(true) != 0) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	if (pipeLoadPids(argv[0][0]) < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids"); return EXIT_FAILURE;}
	if (pipeLoadKeys(argv[0][0]) < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears keys"); return EXIT_FAILURE;}
	if (pipeLoadTls(argv[0][0])  < 0) {syslog(LOG_ERR, "Terminating: Failed loading TLS cert/key"); return EXIT_FAILURE;}
	close(argv[0][0]);

	takeConnections();

	mbedtls_x509_crt_free(&tlsCrt);
	mbedtls_pk_free(&tlsKey);
	sodium_free(tls_crt);
	sodium_free(tls_key);
	return EXIT_SUCCESS;
}
