#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <locale.h> // for setlocale
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <sodium.h>
#include <mbedtls/ssl.h>

#include "delivery.h"
#include "smtp.h"

#include "../Global.h"

#define AEM_PIPE_BUFSIZE 8192
#define AEM_MINLEN_PIPEREAD 128
#define AEM_SOCKET_TIMEOUT 30

static mbedtls_x509_crt tlsCrt;
static mbedtls_pk_context tlsKey;

static unsigned char *tls_crt;
static unsigned char *tls_key;
static size_t len_tls_crt;
static size_t len_tls_key;

static bool terminate = false;

static void sigTerm() {
	syslog(LOG_MAIL | LOG_NOTICE, "Terminating after handling next connection");
	terminate = true;
}

static int setCaps(const bool allowBind) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	cap_t caps = cap_get_proc();
	if (cap_clear(caps) != 0) return -1;

	if (allowBind) {
		const cap_value_t capBind = CAP_NET_BIND_SERVICE;
		if (cap_set_flag(caps, CAP_PERMITTED, 1, &capBind, CAP_SET) != 0) return -1;
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &capBind, CAP_SET) != 0) return -1;
	}

	if (cap_set_proc(caps) != 0) return -1;
	if (cap_free(caps) != 0) return -1;

	return 0;
}

__attribute__((warn_unused_result))
static int initSocket(const int * const sock, const int port) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	const int optval = 1;
	setsockopt(*sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&optval, sizeof(int));

	const int ret = bind(*sock, (struct sockaddr*)&servAddr, sizeof(servAddr));
	if (setCaps(false) != 0) return -1;
	if (ret < 0) return ret;

	listen(*sock, 10); // socket, backlog (# of connections to keep in queue)
	return 0;
}

static void setSocketTimeout(const int sock) {
	struct timeval tv;
	tv.tv_sec = AEM_SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
}

static int takeConnections(void) {
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) return EXIT_FAILURE;
	if (initSocket(&sock, AEM_PORT_SMTP) != 0) return EXIT_FAILURE;

	if (tlsSetup(&tlsCrt, &tlsKey) != 0) return EXIT_FAILURE;

	syslog(LOG_MAIL | LOG_NOTICE, "Ready");

	struct sockaddr_in clientAddr;
	unsigned int clen = sizeof(clientAddr);

	while (!terminate) {
		const int newSock = accept(sock, (struct sockaddr*)&clientAddr, &clen);
		if (newSock < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed creating socket"); break;}
		setSocketTimeout(newSock);
		respond_smtp(newSock, &clientAddr);
		close(newSock);
	}

	close(sock);
	return EXIT_SUCCESS;
}

__attribute__((warn_unused_result))
int getDomainFromCert() {
	char certInfo[1000];
	mbedtls_x509_crt_info(certInfo, 1000, "AEM_", &tlsCrt);

	char *c = strstr(certInfo, "\nAEM_subject name");
	if (c == NULL) return -1;
	c += 17;

	char * const end = strchr(c, '\n');
	*end = '\0';

	c = strstr(c, ": CN=");
	if (c == NULL) return -1;
	c += 5;

	return setDomain(c, strlen(c));
}

__attribute__((warn_unused_result))
static int pipeRead(const int fd, unsigned char ** const target, size_t * const len) {
	unsigned char buf[AEM_PIPE_BUFSIZE];
	const off_t readBytes = read(fd, buf, AEM_PIPE_BUFSIZE);
	if (readBytes < AEM_MINLEN_PIPEREAD) {syslog(LOG_MAIL | LOG_NOTICE, "pipeRead(): %s", strerror(errno)); return -1;}

	*len = readBytes;
	*target = sodium_malloc(*len);
	memcpy(*target, buf, *len);
	sodium_mprotect_readonly(*target);

	sodium_memzero(buf, AEM_PIPE_BUFSIZE);
	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadTls(const int fd) {
	if (
	   pipeRead(fd, &tls_crt, &len_tls_crt) != 0
	|| pipeRead(fd, &tls_key, &len_tls_key) != 0
	) return -1;

	mbedtls_x509_crt_init(&tlsCrt);
	int ret = mbedtls_x509_crt_parse(&tlsCrt, tls_crt, len_tls_crt);
	if (ret != 0) {syslog(LOG_MAIL | LOG_NOTICE, "mbedtls_x509_crt_parse returned %d\n", ret); return -1;}

	mbedtls_pk_init(&tlsKey);
	ret = mbedtls_pk_parse_key(&tlsKey, tls_key, len_tls_key, NULL, 0);
	if (ret != 0) {syslog(LOG_MAIL | LOG_NOTICE, "mbedtls_pk_parse_key returned %d\n", ret); return -1;}

	if (getDomainFromCert() != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed to get domain from certificate"); return -1;}

	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadKeys(const int fd) {
	unsigned char buf[AEM_PIPE_BUFSIZE];

	if (read(fd, buf, AEM_PIPE_BUFSIZE) != AEM_LEN_ACCESSKEY) {syslog(LOG_MAIL | LOG_NOTICE, "pipeRead(): %s", strerror(errno)); return -1;}
	setAccessKey_account(buf);

	if (read(fd, buf, AEM_PIPE_BUFSIZE) != AEM_LEN_ACCESSKEY) {syslog(LOG_MAIL | LOG_NOTICE, "pipeRead(): %s", strerror(errno)); return -1;}
	setAccessKey_storage(buf);

	sodium_memzero(buf, AEM_PIPE_BUFSIZE);
	return 0;
}

__attribute__((warn_unused_result))
static int setSignals(void) {
	return (
	   signal(SIGPIPE, SIG_IGN) != SIG_ERR

	&& signal(SIGINT,  sigTerm) != SIG_ERR
	&& signal(SIGQUIT, sigTerm) != SIG_ERR
	&& signal(SIGTERM, sigTerm) != SIG_ERR
	&& signal(SIGUSR1, sigTerm) != SIG_ERR
	&& signal(SIGUSR2, sigTerm) != SIG_ERR
	) ? 0 : -1;
}

int main(int argc, char *argv[]) {
	setlocale(LC_ALL, "C");

	if (argc > 1 || argv == NULL) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Invalid arguments"); return EXIT_FAILURE;}
	if (getuid()      == 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Must not be started as root"); return EXIT_FAILURE;}
	if (setCaps(true) != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}
	if (setSignals()  != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed setting up signal handling"); return EXIT_FAILURE;}
	if (sodium_init()  < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed initializing libsodium"); return EXIT_FAILURE;}

	if (pipeLoadKeys(argv[0][0]) < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed loading All-Ears keys"); return EXIT_FAILURE;}
	if (pipeLoadTls(argv[0][0])  < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed loading TLS cert/key"); return EXIT_FAILURE;}
	close(argv[0][0]);

	takeConnections();
	syslog(LOG_MAIL | LOG_NOTICE, "Terminating");
	return EXIT_SUCCESS;
}
