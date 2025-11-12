#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <syslog.h>

#include <sodium.h>

#include "../Global.h"
#include "Error.h"

#include "Respond.h"

static unsigned char rbk[AEM_API_BODY_KEYSIZE];

void setRbk(const unsigned char * const newKey) {
	memcpy(rbk, newKey, AEM_API_BODY_KEYSIZE);
}

void clrRbk(void) {
	sodium_memzero(rbk, AEM_API_BODY_KEYSIZE);
}

static int numDigits(const size_t x) {
	return
	(x < 1000 ? 3 :
	(x < 10000 ? 4 :
	(x < 100000 ? 5 :
	(x < 1000000 ? 6 :
	7))));
}

void unauthResponse(const unsigned char code) {
	send(AEM_FD_SOCK_CLIENT,
		(unsigned char[]){'H','T','T','P','/','1','.','0',' ','2','0','4',' ',code,'\r','\n',
		'A','c','c','e','s','s','-','C','o','n','t','r','o','l','-','A','l','l','o','w','-','O','r','i','g','i','n',':',' ','*','\r','\n','\r','\n'}
	, 50, 0);
}

void apiResponse(const unsigned char * const data, const size_t lenData) {
	// Pad original data
	const size_t lenPadding = (lenData % 256 == 0) ? 0 : 256 - (lenData % 256);
	const size_t lenPadded = 1 + lenData + lenPadding;
	const size_t lenFinal = lenPadded + crypto_aead_aegis256_ABYTES;

	unsigned char * const padded = malloc(lenPadded);
	if (padded == NULL) {unauthResponse(AEM_API_UNAUTH_ERR_INTERNAL); syslog(LOG_ERR, "Failed allocation"); return;}
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
	crypto_aead_aegis256_encrypt(response + lenHeaders, NULL, padded, lenPadded, NULL, 0, NULL, rbk, rbk + crypto_aead_aegis256_NPUBBYTES);
	sodium_memzero(padded, lenPadded);
	free(padded);

	// Send
	send(AEM_FD_SOCK_CLIENT, response, lenResponse, 0);
}
