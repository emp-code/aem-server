#include <signal.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/SetCaps.h"

#ifdef AEM_TLS
#define AEM_LOGNAME "AEM-Web-Clr"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "../Common/x509_getCn.h"

WOLFSSL_CTX *ctx;
WOLFSSL *ssl;
#else
#define AEM_LOGNAME "AEM-Web-Oni"
#endif

size_t lenResp;
unsigned char *resp;

static volatile sig_atomic_t terminate = 0;
static void sigTerm(const int s) {terminate = 1;}

#include "../Common/Main_Include.c"

#ifdef AEM_TLS
static int lenSts;
static char sts[512];

static int setKeyShare(void) {
	for(;;) {
		const int ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);
		if (ret == WOLFSSL_SUCCESS) break;
		if (ret != WC_PENDING_E) return -1;
	}

	return (wolfSSL_set_groups(ssl, (int[]){WOLFSSL_ECC_X25519}, 1) == WOLFSSL_SUCCESS) ? 0 : -1;
}
#endif

static int acceptClients(void) {
#ifdef AEM_LOCAL
	const int sock = createSocket(true, 10, 10);
#else
	const int sock = createSocket(false, 10, 10);
#endif
	if (sock < 0) return -10;
	if (setCaps(0) != 0) return -11;

	syslog(LOG_INFO, "Ready");

	while (terminate == 0) {
		const int newSock = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (newSock < 0) continue;

#ifdef AEM_TLS
		ssl = wolfSSL_new(ctx);
		if (ssl == NULL) {close(newSock); continue;}
		setKeyShare();

		if (
		   wolfSSL_set_fd(ssl, newSock) != WOLFSSL_SUCCESS
		|| wolfSSL_accept_TLSv13(ssl) != WOLFSSL_SUCCESS
		|| wolfSSL_state(ssl) != 0) {
			close(newSock);
			continue;
		}

		unsigned char req[29];
		if (wolfSSL_read(ssl, req, 29) == 29) {
			if (memcmp(req, "GET /.well-known/mta-sts.txt ", 29) == 0) {
				wolfSSL_write(ssl, sts, lenSts);
			} if (memcmp(req, "GET / HTTP/1.", 13) == 0) {
				wolfSSL_write(ssl, resp, lenResp);
			} else {
				close(newSock);
				wolfSSL_free(ssl);
				continue;
			}
		}

		wolfSSL_shutdown(ssl);
		wolfSSL_free(ssl);
#else
		shutdown(newSock, SHUT_RD);
		write(newSock, resp, lenResp);
#endif
		close(newSock);
	}

#ifdef AEM_TLS
	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
#endif

	close(sock);
	return 0;
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
			if (read(AEM_FD_PIPE_RD, resp + (lenResp - tbr), tbr) != (ssize_t)tbr) return 4;
			break;
		}
	}

#ifdef AEM_TLS
	wolfSSL_Init();

	ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
	if (ctx == NULL) return 10;

	if (wolfSSL_CTX_SetMinVersion(ctx, 4) != WOLFSSL_SUCCESS) return 11;
	if (wolfSSL_CTX_set_cipher_list(ctx, "TLS_AES_256_GCM_SHA384") != WOLFSSL_SUCCESS) return 12; // TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
	wolfSSL_CTX_no_ticket_TLSv13(ctx);

	size_t lenTlsCrt;
	size_t lenTlsKey;
	unsigned char tlsCrt[PIPE_BUF];
	unsigned char tlsKey[PIPE_BUF];

	if (
	   read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsCrt, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsCrt, lenTlsCrt) != (ssize_t)lenTlsCrt
	|| read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsKey, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsKey, lenTlsKey) != (ssize_t)lenTlsKey
	) return 13;

	if (wolfSSL_CTX_use_certificate_chain_buffer(ctx, tlsCrt, lenTlsCrt) != WOLFSSL_SUCCESS) {sodium_memzero(tlsCrt, lenTlsCrt); sodium_memzero(tlsKey, lenTlsKey); return 14;}
	if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, tlsKey, lenTlsKey, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {sodium_memzero(tlsCrt, lenTlsCrt); sodium_memzero(tlsKey, lenTlsKey); return 15;}

	unsigned char cn[100];
	size_t lenCn;
	if (x509_getSubject(cn, &lenCn, tlsCrt, lenTlsCrt) != 0) return 16;

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
#endif

	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"
	const int pr = pipeRead();
	close(AEM_FD_PIPE_RD);
	if (pr != 0) return pr;

	return acceptClients();
}
