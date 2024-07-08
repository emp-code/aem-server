#ifdef AEM_TLS
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "../Global.h"

#include "ClientTLS.h"

static WOLFSSL_CTX *ctx;
static WOLFSSL *ssl;

static int setKeyShare(void) {
	for(;;) {
		const int ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);
		if (ret == WOLFSSL_SUCCESS) break;
		if (ret != WC_PENDING_E) return -1;
	}

	return (wolfSSL_set_groups(ssl, (int[]){WOLFSSL_ECC_X25519}, 1) == WOLFSSL_SUCCESS) ? 0 : -1;
}

int tls_init(const unsigned char * const crt, const size_t lenCrt, const unsigned char * const key, const size_t lenKey, const unsigned char * const domain, const size_t lenDomain) {
	wolfSSL_Init();

	ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
	if (ctx == NULL) return 10;

	if (wolfSSL_CTX_SetMinVersion(ctx, 4) != WOLFSSL_SUCCESS) return 11;
	if (wolfSSL_CTX_set_cipher_list(ctx, "TLS_AES_256_GCM_SHA384") != WOLFSSL_SUCCESS) return 12;
	wolfSSL_CTX_no_ticket_TLSv13(ctx);

	if (wolfSSL_CTX_use_certificate_chain_buffer(ctx, crt, lenCrt) != WOLFSSL_SUCCESS) return 13;
	if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, lenKey, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) return 14;
	if (wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, domain, lenDomain) != WOLFSSL_SUCCESS) return 15;

	return 0;
}

void tls_free(void) {
	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();
}

int tls_connect(void) {
	ssl = wolfSSL_new(ctx);
	if (ssl == NULL) return -1;
	setKeyShare();

	return (
		wolfSSL_set_fd(ssl, AEM_FD_SOCK_CLIENT) == WOLFSSL_SUCCESS
	&& wolfSSL_accept_TLSv13(ssl) == WOLFSSL_SUCCESS
	&& wolfSSL_state(ssl) == 0) ? 0 : -1;
}

void tls_disconnect(void) {
	wolfSSL_shutdown(ssl);
	wolfSSL_free(ssl);
}

int tls_peek(unsigned char * const buf, const size_t len) {
	return wolfSSL_peek(ssl, buf, len);
}

int tls_recv(unsigned char * const buf, const size_t len) {
	return wolfSSL_read(ssl, buf, len);
}

int tls_send(const void * const buf, const size_t len) {
	return wolfSSL_write(ssl, buf, len);
}

#endif
