#include <arpa/inet.h>
#include <locale.h> // for setlocale
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sodium.h>
#include <mbedtls/ssl.h>

#include "global.h"
#include "https.h"
#include "https_get.h"

#define AEM_CHROOT "/var/lib/allears/web-files"
#define AEM_PORT_HTTPS 443
#define AEM_PATH_TLSKEY "/etc/allears/TLS.key"
#define AEM_PATH_TLSCRT "/etc/allears/TLS.crt"
#define AEM_SOCKET_TIMEOUT 15

char domain[AEM_MAXLEN_HOST];
size_t lenDomain;

static bool terminate = false;

static void sigTerm() {
	puts("Terminating after handling next connection");
	terminate = true;
}

__attribute__((warn_unused_result))
static int dropRoot(void) {
	const struct passwd * const p = getpwnam("nobody");
	if (p == NULL) return -1;

	if (chroot(AEM_CHROOT) != 0) return -1;
	if (chdir("/") != 0) return -1;

	if (setgid(p->pw_gid) != 0) return -1;
	if (setuid(p->pw_uid) != 0) return -1;

	if (getgid() != p->pw_gid || getuid() != p->pw_uid) return -1;

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
	if (ret < 0) return ret;

	listen(*sock, 10); // socket, backlog (# of connections to keep in queue)
	return 0;
}

__attribute__((warn_unused_result))
static int loadTlsKey(mbedtls_pk_context * const key) {
	mbedtls_pk_init(key);
	const int ret = mbedtls_pk_parse_keyfile(key, AEM_PATH_TLSKEY, NULL);
	if (ret == 0) return 0;

	printf("mbedtls_pk_parse_key returned %d\n", ret);
	return 1;
}

static void setSocketTimeout(const int sock) {
	struct timeval tv;
	tv.tv_sec = AEM_SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
}

static int receiveConnections(mbedtls_x509_crt * const tlsCert) {
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) return EXIT_FAILURE;

	if (initSocket(&sock, AEM_PORT_HTTPS) != 0) return EXIT_FAILURE;

	mbedtls_pk_context tlsKey;
	if (loadTlsKey(&tlsKey) < 0) return EXIT_FAILURE;
	if (dropRoot() != 0) {mbedtls_pk_free(&tlsKey); return EXIT_FAILURE;}

	if (loadFile(AEM_FILETYPE_CSS)  != 0) {puts("Terminating: Failed to load main.css"); mbedtls_pk_free(&tlsKey); return EXIT_FAILURE;}
	if (loadFile(AEM_FILETYPE_HTML) != 0) {puts("Terminating: Failed to load index.html"); mbedtls_pk_free(&tlsKey); return EXIT_FAILURE;}
	if (loadFile(AEM_FILETYPE_JSAE) != 0) {puts("Terminating: Failed to load all-ears.js"); mbedtls_pk_free(&tlsKey); return EXIT_FAILURE;}
	if (loadFile(AEM_FILETYPE_JSMN) != 0) {puts("Terminating: Failed to load main.js"); mbedtls_pk_free(&tlsKey); return EXIT_FAILURE;}

	if (tlsSetup(tlsCert, &tlsKey) != 0) {mbedtls_pk_free(&tlsKey); return EXIT_FAILURE;}

	puts("Ready");

	while (!terminate) {
		const int newSock = accept(sock, NULL, NULL);
		if (newSock < 0) {puts("Failed to create socket for accepting connection"); break;}
		setSocketTimeout(newSock);
		respond_https(newSock);
		close(newSock);
	}

	tlsFree();
	mbedtls_pk_free(&tlsKey);
	freeFiles();
	close(sock);
	return EXIT_SUCCESS;
}

__attribute__((warn_unused_result))
static int getDomainFromCert(mbedtls_x509_crt * const cert) {
	char certInfo[1000];
	mbedtls_x509_crt_info(certInfo, 1000, "AEM_", cert);

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

int main(void) {
	if (getuid() != 0) {
		puts("Terminating: Must be started as root");
		return EXIT_FAILURE;
	}

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) { // Prevent writing to closed/invalid sockets from ending the process
		puts("Terminating: signal failed");
		return EXIT_FAILURE;
	}

	signal(SIGINT, sigTerm);
	signal(SIGQUIT, sigTerm);
	signal(SIGTERM, sigTerm);

	if (sodium_init() < 0) {
		puts("Terminating: Failed to initialize libsodium");
		return EXIT_FAILURE;
	}

	setlocale(LC_ALL, "C");

	// Get domain from TLS certificate
	mbedtls_x509_crt tlsCert;
	mbedtls_x509_crt_init(&tlsCert);
	int ret = mbedtls_x509_crt_parse_file(&tlsCert, AEM_PATH_TLSCRT);
	if (ret != 0) {
		printf("Terminating: mbedtls_x509_crt_parse returned %d\n", ret);
		return EXIT_FAILURE;
	}

	if (getDomainFromCert(&tlsCert) != 0) {
		puts("Terminating: Failed to load domain name from TLS certificate");
		return EXIT_FAILURE;
	}

	printf("Domain detected as '%.*s'\n", (int)lenDomain, domain);

	ret = receiveConnections(&tlsCert);
	mbedtls_x509_crt_free(&tlsCert);
	return ret;
}
