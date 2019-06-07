#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"

#include "defines.h"

//#include "aef.h"
#include "http.h"
#include "https.h"
//#include "smtp.h"

// Allow restarting the server immediately after kill
static void allowQuickRestart(const int* sock) {
	const int optval = 1;
	setsockopt(*sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&optval, sizeof(int));
}

static int initSocket(int *sock, const int port) {
	*sock = socket(AF_INET, SOCK_STREAM, 0);
	if (*sock < 0) {
		puts("ERROR: Opening socket failed");
		return 1;
	}

	allowQuickRestart(sock);

	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	const int ret = bind(*sock, (struct sockaddr*)&servAddr, sizeof(servAddr));
	if (ret < 0) return ret;

	listen(*sock, 10); // socket, backlog (# of connections to keep in queue)
	return 0;
}

/*static int receiveConnections_aef() {
	int sock;
	if (initSocket(&sock, AEM_PORT_AEF) != 0) return 1;

	while(1) {
		const int sockNew = accept(sock, NULL, NULL);
		respond_aef(sockNew);
		close(sockNew);
	}

	return 0;
}*/

static int receiveConnections_http() {
	int sock;
	if (initSocket(&sock, AEM_PORT_HTTP) != 0) return 1;

	while(1) {
		const int sockNew = accept(sock, NULL, NULL);
		respond_http(sockNew);
		close(sockNew);
	}

	return 0;
}

static int receiveConnections_https(const int port) {
	int sock;
	if (initSocket(&sock, port) != 0) return 1;

	// Load certs
	int fd = open("aem-https.crt", O_RDONLY);
	if (fd < 0) return 1;
	off_t lenFile = lseek(fd, 0, SEEK_END);

	unsigned char *cert = calloc(lenFile + 2, 1);
	ssize_t readBytes = pread(fd, cert, lenFile, 0);
	close(fd);
	if (readBytes != lenFile) {free(cert); return 2;}

	mbedtls_x509_crt srvcert;
	mbedtls_x509_crt_init(&srvcert);
	int ret = mbedtls_x509_crt_parse(&srvcert, cert, lenFile + 1);
	free(cert);

	if (ret != 0) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		printf("ERROR: Loading server cert failed - mbedtls_x509_crt_parse returned %d: %s\n", ret, error_buf);
		return 1;
	}

	// Load key
	fd = open("aem-https.key", O_RDONLY);
	if (fd < 0) return 1;
	lenFile = lseek(fd, 0, SEEK_END);
	
	unsigned char *key = calloc(lenFile + 2, 1);
	readBytes = pread(fd, key, lenFile, 0);
	close(fd);
	if (readBytes != lenFile) {free(key); return 1;}

	mbedtls_pk_context pkey;
	mbedtls_pk_init(&pkey);
	ret = mbedtls_pk_parse_key(&pkey, key, lenFile + 2, NULL, 0);
	if (ret != 0) {printf("ERROR: mbedtls_pk_parse_key returned %x\n", ret); return 1;}

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) return 1;
	unsigned char seed[16];
	readBytes = read(fd, seed, 16);
	if (readBytes != 16) return 3;
	close(fd);

	// Seed the RNG
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, 16)) != 0) {
		printf("ERROR: mbedtls_ctr_drbg_seed returned %d\n", ret);
		return 1;
	}

	// Setting up the SSL
	mbedtls_ssl_config conf;
	mbedtls_ssl_config_init(&conf);

	if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		printf("Failed; mbedtls_ssl_config_defaults returned %d\n\n", ret);
	}

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
	if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
		printf("ERROR: mbedtls_ssl_conf_own_cert returned %d\n", ret);
		return 1;
	}

	while(1) {
		struct sockaddr_in clientAddr;
		unsigned int clen = sizeof(clientAddr);
		int sockNew = accept(sock, (struct sockaddr*)&clientAddr, &clen);

		mbedtls_ssl_context ssl;
		mbedtls_ssl_init(&ssl);
		if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {printf("ERROR: mbedtls_ssl_setup returned %d\n", ret); continue;}

		mbedtls_ssl_set_bio(&ssl, &sockNew, mbedtls_net_send, mbedtls_net_recv, NULL);

		// Handshake
		int ret;
		while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
			if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				/*if (ret == -80) {
					mbedtls_ssl_session_reset(ssl);
					continue;
				}*/

				char error_buf[100];
				mbedtls_strerror(ret, error_buf, 100);
				printf("ERROR: mbedtls_ssl_handshake returned %d: %s\n", ret, error_buf);
				mbedtls_ssl_session_reset(&ssl);
				mbedtls_ssl_free(&ssl);
				break;
			}
		} if (ret != 0) continue;

		respond_https(&ssl, clientAddr.sin_addr.s_addr, seed);

		mbedtls_ssl_session_reset(&ssl);
		mbedtls_ssl_free(&ssl);
		close(sockNew);
	}

	mbedtls_x509_crt_free(&srvcert);
	mbedtls_pk_free(&pkey);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return 0;
}

/*static int receiveConnections_smtp() {
	int sock;
	if (initSocket(&sock, AEM_PORT_SMTP) != 0) return 1;

	while(1) {
		const int sockNew = accept(sock, NULL, NULL);
		respond_smtp(sockNew);
		close(sockNew);
	}

	return 0;
}*/

int main() {
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {puts("ERROR: signal failed"); return 4;} // Prevent zombie processes

	puts(">>> ae-mail: All-Ears Mail");

	int pid;
	
	pid = fork();
	if (pid < 0) return 1;
	if (pid == 0) return 0; //receiveConnections(AEM_PORT_AEF);

	pid = fork();
	if (pid < 0) return 1;
	if (pid == 0) return receiveConnections_https(AEM_PORT_HTTPS);

	pid = fork();
	if (pid < 0) return 1;
//	if (pid == 0) return receiveConnections(AEM_PORT_SMTP);

	receiveConnections_http(AEM_PORT_HTTP);

	return 0;
}
