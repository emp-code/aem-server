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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium.h>
#include <mbedtls/ssl.h>

#include "Include/Brotli.h"
#include "Include/Database.h"
#include "smtp.h"

#define AEM_CHROOT "/var/lib/allears" // Ownership root:allears; permissions 730 (rwx-wx---)
#define AEM_PORT_SMTP 25
#define AEM_PATH_ADDRKEY "/etc/allears/Address.key"
#define AEM_PATH_TLSKEY "/etc/allears/TLS.key"
#define AEM_PATH_TLSCRT "/etc/allears/TLS.crt"
#define AEM_SOCKET_TIMEOUT 30

static bool terminate = false;

static void sigTerm() {
	puts("Terminating after handling next connection");
	terminate = true;
}

__attribute__((warn_unused_result))
static int dropRoot(void) {
	const struct passwd * const p = getpwnam("allears");
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

__attribute__((warn_unused_result))
static int loadAddrKey(void) {
	const int fd = open(AEM_PATH_ADDRKEY, O_RDONLY);
	if (fd < 0 || lseek(fd, 0, SEEK_END) != crypto_pwhash_SALTBYTES) return 1;

	unsigned char addrKey[crypto_pwhash_SALTBYTES];
	const off_t readBytes = pread(fd, addrKey, crypto_pwhash_SALTBYTES, 0);
	close(fd);

	if (readBytes != crypto_pwhash_SALTBYTES) {
		printf("pread returned: %ld\n", readBytes);
		return -1;
	}

	setAddrKey(addrKey);
	sodium_memzero(addrKey, crypto_pwhash_SALTBYTES);
	return 0;
}

static void setSocketTimeout(const int sock) {
	struct timeval tv;
	tv.tv_sec = AEM_SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
}

static int receiveConnections(mbedtls_x509_crt * const tlsCert) {
	mbedtls_pk_context tlsKey;
	if (loadTlsKey(&tlsKey) < 0) return EXIT_FAILURE;

	if (loadAddrKey() < 0) {
		puts("Terminating: failed to load address key");
		return EXIT_FAILURE;
	}

	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) return EXIT_FAILURE;
	if (initSocket(&sock, AEM_PORT_SMTP) != 0) return EXIT_FAILURE;

	if (dropRoot() != 0) {mbedtls_pk_free(&tlsKey); return EXIT_FAILURE;}

	if (tlsSetup(tlsCert, &tlsKey) != 0) {mbedtls_pk_free(&tlsKey); return EXIT_FAILURE;}

	puts("Ready");

	struct sockaddr_in clientAddr;
	unsigned int clen = sizeof(clientAddr);

	while (!terminate) {
		const int newSock = accept(sock, (struct sockaddr*)&clientAddr, &clen);
		if (newSock < 0) {puts("Failed to create socket for accepting connection"); break;}
		setSocketTimeout(newSock);
		respond_smtp(newSock, &clientAddr);
		close(newSock);
	}

	tlsFree();
	mbedtls_pk_free(&tlsKey);
	close(sock);
	return EXIT_SUCCESS;
}

__attribute__((warn_unused_result))
int getDomainFromCert(mbedtls_x509_crt * const cert) {
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

	return setDomain(c, strlen(c));
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

	ret = getDomainFromCert(&tlsCert);
	if (ret != 0) {puts("Terminating: Failed to get domain from certificate"); return EXIT_FAILURE;}

	ret = receiveConnections(&tlsCert);
	mbedtls_x509_crt_free(&tlsCert);
	return ret;
}
