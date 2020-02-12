#include <arpa/inet.h>
#include <errno.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>
#include <mbedtls/ssl.h>

#include "../Global.h"

#include "global.h"
#include "https.h"
#include "get.h"

#define AEM_PORT_HTTPS 443
#define AEM_SOCKET_TIMEOUT 15
#define AEM_MINLEN_PIPEREAD 128

#define AEM_PIPE_BUFSIZE 8192

static mbedtls_x509_crt tlsCrt;
static mbedtls_pk_context tlsKey;

static unsigned char *tls_crt;
static unsigned char *tls_key;
static size_t len_tls_crt;
static size_t len_tls_key;

char domain[AEM_MAXLEN_HOST];
size_t lenDomain;

static bool terminate = false;

static void sigTerm(const int sig) {
	if (sig == SIGUSR1) {
		terminate = true;
		syslog(LOG_MAIL | LOG_NOTICE, "Terminating after next connection");
		return;
	}

	// SIGUSR2: Fast kill
	freeFiles();
	mbedtls_x509_crt_free(&tlsCrt);
	mbedtls_pk_free(&tlsKey);
	sodium_free(tls_crt);
	sodium_free(tls_key);
	syslog(LOG_MAIL | LOG_NOTICE, "Terminating immediately");
	exit(EXIT_SUCCESS);
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
static int initSocket(const int sock, const int port) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	const int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&optval, sizeof(int));

	if (bind(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) return -1;
	if (setCaps(false) != 0) return -1;

	listen(sock, 10); // socket, backlog (# of connections to keep in queue)
	return 0;
}

__attribute__((warn_unused_result))
static int getDomainFromCert(void) {
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

	lenDomain = strlen(c);
	if (lenDomain > AEM_MAXLEN_HOST) return -1;

	memcpy(domain, c, lenDomain);
	return 0;
}

// For handling large reads on O_DIRECT pipes
static ssize_t pipeReadDirect(const int fd, unsigned char *buf, const size_t maxLen) {
	ssize_t readBytes = 0;

	while(1) {
		const ssize_t ret = read(fd, buf + readBytes, maxLen - readBytes);
		if (ret < 1) return -1;

		readBytes += ret;
		if (ret != PIPE_BUF) return readBytes;
	}
}

__attribute__((warn_unused_result))
static int pipeRead(const int fd, unsigned char ** const target, size_t * const len) {
	unsigned char buf[AEM_PIPE_BUFSIZE];
	const off_t readBytes = pipeReadDirect(fd, buf, AEM_PIPE_BUFSIZE);
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
static int pipeLoadFiles(const int fd) {
	unsigned char *buf;
	size_t len;

	if (pipeRead(fd, &buf, &len) != 0) return -1;
	setResponse(AEM_FILETYPE_CSS, buf, len);

	if (pipeRead(fd, &buf, &len) != 0) return -1;
	setResponse(AEM_FILETYPE_HTM, buf, len);

	if (pipeRead(fd, &buf, &len) != 0) return -1;
	setResponse(AEM_FILETYPE_JSA, buf, len);

	if (pipeRead(fd, &buf, &len) != 0) return -1;
	setResponse(AEM_FILETYPE_JSM, buf, len);

	return 0;
}

static void setSocketTimeout(const int sock) {
	struct timeval tv;
	tv.tv_sec = AEM_SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
}

static void quit(void) {
	sodium_free(tls_crt);
	sodium_free(tls_key);
	syslog(LOG_MAIL | LOG_NOTICE, "Terminating");
	exit(EXIT_SUCCESS);
}

static void receiveConnections(void) {
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed creating socket"); close(sock); exit(EXIT_FAILURE);}
	if (initSocket(sock, AEM_PORT_HTTPS) != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed creating socket"); close(sock); exit(EXIT_FAILURE);}
	if (tlsSetup(&tlsCrt, &tlsKey) != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed setting up TLS"); close(sock); exit(EXIT_FAILURE);}

	syslog(LOG_MAIL | LOG_NOTICE, "Ready");

	while (!terminate) {
		const int newSock = accept(sock, NULL, NULL);
		if (newSock < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed accepting connection"); break;}
		setSocketTimeout(newSock);
		respond_https(newSock);
		close(newSock);
	}

	tlsFree();
	mbedtls_x509_crt_free(&tlsCrt);
	mbedtls_pk_free(&tlsKey);
	close(sock);
}

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

	if (pipeLoadTls(argv[0][0])   < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed loading TLS cert/key"); return EXIT_FAILURE;}
	if (pipeLoadFiles(argv[0][0]) < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed loading files"); return EXIT_FAILURE;}
	close(argv[0][0]);

	atexit(quit);

	receiveConnections();
	return EXIT_SUCCESS;
}
