#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

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
	send(AEM_FD_SOCK_CLIENT,
		"HTTP/1.1 403 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71, 0);
}

void respond403(void) {
	send(AEM_FD_SOCK_CLIENT,
		"HTTP/1.1 403 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71, 0);
}

void respond404(void) {
	send(AEM_FD_SOCK_CLIENT,
		"HTTP/1.1 404 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71, 0);
}

void respond500(void) {
	send(AEM_FD_SOCK_CLIENT,
		"HTTP/1.1 500 aem\r\n"
		"Content-Length: 0\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"\r\n"
	, 71, 0);
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
		"HTTP/1.1 200 aem\r\n"
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

	// Send the response
	send(AEM_FD_SOCK_CLIENT, response, lenResponse, 0);

	// Make sure the response is sent before closing the socket
	shutdown(AEM_FD_SOCK_CLIENT, SHUT_WR);
	unsigned char x[1024];
	read(AEM_FD_SOCK_CLIENT, x, 1024);
	read(AEM_FD_SOCK_CLIENT, x, 1024);
}
