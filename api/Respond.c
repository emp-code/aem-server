#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#ifdef AEM_TLS
#include "ClientTLS.h"
#else
#include <sys/socket.h>
#endif

#include <sodium.h>

#include "../Global.h"

#include "Respond.h"

static unsigned char rbk[crypto_aead_aes256gcm_KEYBYTES];

void setRbk(const unsigned char * const newKey) {
	memcpy(rbk, newKey, crypto_aead_aes256gcm_KEYBYTES);
}

void clrRbk(void) {
	sodium_memzero(rbk, crypto_aead_aes256gcm_KEYBYTES);
}

static int numDigits(const size_t x) {
	return
	(x < 100 ? 2 :
	(x < 1000 ? 3 :
	(x < 10000 ? 4 :
	(x < 100000 ? 5 :
	(x < 1000000 ? 6 :
	7)))));
}

void respond400(void) {
#ifdef AEM_TLS
	tls_send(
		"HTTP/1.0 400 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71);
#else
	send(AEM_FD_SOCK_CLIENT,
		"HTTP/1.0 400 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71, 0);
#endif
}

void respond403(void) {
#ifdef AEM_TLS
	tls_send(
		"HTTP/1.0 403 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71);
#else
	send(AEM_FD_SOCK_CLIENT,
		"HTTP/1.0 403 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71, 0);
#endif
}

void respond404(void) {
#ifdef AEM_TLS
	tls_send(
		"HTTP/1.0 404 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71);
#else
	send(AEM_FD_SOCK_CLIENT,
		"HTTP/1.0 404 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71, 0);
#endif
}

void respond408(void) {
#ifdef AEM_TLS
	tls_send(
		"HTTP/1.0 408 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71);
#else
	send(AEM_FD_SOCK_CLIENT,
		"HTTP/1.0 408 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71, 0);
#endif
}

void respond500(void) {
#ifdef AEM_TLS
	tls_send(
		"HTTP/1.0 500 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71);
#else
	send(AEM_FD_SOCK_CLIENT,
		"HTTP/1.0 500 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71, 0);
#endif
}

void apiResponse(const unsigned char * const data, const size_t lenData) {
	// Pad original data
	const size_t lenPadding = (lenData % 256 == 0) ? 0 : 256 - (lenData % 256);
	const size_t lenPadded = 1 + lenData + lenPadding;
	const size_t lenFinal = lenPadded + crypto_aead_aes256gcm_ABYTES;

	unsigned char * const padded = malloc(lenPadded);
	if (padded == NULL) {respond500(); syslog(LOG_ERR, "Failed allocation"); return;}
	padded[0] = lenPadding;
	memcpy(padded + 1, data, lenData);
	randombytes_buf(padded + lenPadded - lenPadding, lenPadding);

	// Add headers
	const size_t lenHeaders = 70 + numDigits(lenFinal);
	const size_t lenResponse = lenHeaders + lenFinal;
	unsigned char response[lenResponse];
	sprintf((char*)response,
		"HTTP/1.0 200 aem\r\n"
		"Content-Length: %zu\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, lenFinal);

	// Add encrypted response
	unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
	bzero(nonce, crypto_aead_aes256gcm_NPUBBYTES);

	crypto_aead_aes256gcm_encrypt(response + lenHeaders, NULL, padded, lenPadded, NULL, 0, NULL, nonce, rbk);
	sodium_memzero(padded, lenPadded);
	free(padded);

	// Send
#ifdef AEM_TLS
	tls_send(response, lenResponse);
#else
	send(AEM_FD_SOCK_CLIENT, response, lenResponse, 0);
#endif
}
