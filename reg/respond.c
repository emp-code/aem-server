#include <string.h>
#include <stddef.h>
#include <sys/socket.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/binTs.h"
#include "../IntCom/Client.h"

#include "respond.h"

/*
	42 BinTs_Server
	30 BinTs_User_offset
	[AEGIS-256] 320 UAK
	[AEGIS-256] 256 MAC
648 bits; 81 bytes; 108 chars
*/
#define AEM_REQ_LEN 81
#define AEM_REQ_B64_LEN 108
#define AEM_REQ_LINE1_LEN (7 + AEM_REQ_B64_LEN)

#undef AEM_TLS // TLS unsupported for now

#ifdef AEM_TLS
#define AEM_RESPOND_FALSE false
#else
#define AEM_RESPOND_FALSE 
#endif

static void reg_process(const unsigned char * const req) {
	const long long  binTs_server = ((long long)req[0]) | ((long long)req[1] << 8) | ((long long)req[2] << 16) | ((long long)req[3] << 24) | ((long long)req[4] << 32) | ((long long)(req[5] & 3) << 40);
	const long long binTs_user = binTs_server + ((req[5] >> 2) | (req[6] << 6) | (req[7] << 14) | (req[8] << 22));
	if (llabs(binTs_user - (long long)getBinTs()) > AEM_API_TIMEDIFF_REG) return;

	unsigned char *resp = NULL;
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_ACC, 0, req, AEM_REQ_LEN, &resp, 33);

	if (icRet == 33) {
		unsigned char r[93];
		sodium_bin2base64((char*)r + 13, 45, resp, 33, sodium_base64_VARIANT_URLSAFE);
		memcpy(r, "HTTP/1.0 200 ", 13);
		memcpy(r + 57, "\r\nAccess-Control-Allow-Origin: *\r\n\r\n", 36);

#ifdef AEM_TLS
		tls_send(
#else
		send(AEM_FD_SOCK_CLIENT,
#endif
		r, 93
#ifndef AEM_TLS
		, 0
#endif
		);
	}

	if (resp != NULL) free(resp);
}

#ifdef AEM_TLS
bool
#else
void
#endif
 respondClient(void) {
	 unsigned char r[AEM_REQ_LINE1_LEN];

	if (
#ifdef AEM_TLS
	tls_recv(r, AEM_REQ_LINE1_LEN)
#else
	recv(AEM_FD_SOCK_CLIENT, r, AEM_REQ_LINE1_LEN, 0)
#endif
	!= AEM_REQ_LINE1_LEN) return AEM_RESPOND_FALSE;

	if (
	   r[0] != 'H' || r[1] != 'E' || r[2] != 'A' || r[3] != 'D' || r[4] != ' ' || r[5] != '/'
	|| r[AEM_REQ_LINE1_LEN - 1] != ' '
	|| strspn((const char *)r + 6, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_") != AEM_REQ_B64_LEN
	) return AEM_RESPOND_FALSE;

	unsigned char req[AEM_REQ_LEN];
	size_t decodedLen = 0;
	sodium_base642bin(req, AEM_REQ_LEN, (const char*)r + 6, AEM_REQ_B64_LEN, NULL, &decodedLen, NULL, sodium_base64_VARIANT_URLSAFE);
	if (decodedLen != AEM_REQ_LEN) return AEM_RESPOND_FALSE;

	reg_process(req);
#ifdef AEM_TLS
	return true;
#endif
}
