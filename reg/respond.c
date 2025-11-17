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
	[AEGIS-256] 344 UAK (338)
	[AEGIS-256] 256 MAC
*/
#define AEM_REQ_LEN 84
#define AEM_REQ_B64_LEN 112
#define AEM_REQ_LINE1_LEN (7 + AEM_REQ_B64_LEN)

void respondClient(void) {
	unsigned char r[AEM_REQ_LINE1_LEN];
	if (recv(AEM_FD_SOCK_CLIENT, r, AEM_REQ_LINE1_LEN, 0) != AEM_REQ_LINE1_LEN) return;

	if (r[0] != 'H' || r[1] != 'E' || r[2] != 'A' || r[3] != 'D' || r[4] != ' ' || r[5] != '/'
	|| r[AEM_REQ_LINE1_LEN - 1] != ' '
	|| strspn((const char *)r + 6, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_") != AEM_REQ_B64_LEN
	) return;

	unsigned char req[AEM_REQ_LEN];
	size_t decodedLen = 0;
	sodium_base642bin(req, AEM_REQ_LEN, (const char*)r + 6, AEM_REQ_B64_LEN, NULL, &decodedLen, NULL, sodium_base64_VARIANT_URLSAFE);
	if (decodedLen != AEM_REQ_LEN) return;

	const long long  binTs_server = ((long long)req[0]) | ((long long)req[1] << 8) | ((long long)req[2] << 16) | ((long long)req[3] << 24) | ((long long)req[4] << 32) | ((long long)(req[5] & 3) << 40);
	const long long binTs_user = binTs_server + ((req[5] >> 2) | (req[6] << 6) | (req[7] << 14) | (req[8] << 22));
	if (llabs(binTs_user - (long long)getBinTs()) > AEM_API_TIMEDIFF_REG) return;

	const int32_t icRet = intcom(AEM_INTCOM_SERVER_ACC, 0, req, AEM_REQ_LEN, NULL, 0);
	send(AEM_FD_SOCK_CLIENT, (unsigned char[]){'H','T','T','P','/','1','.','0',' ','2','0',(icRet == AEM_INTCOM_RESPONSE_OK) ? '4' : '5',' ','A','E','M','\r','\n','\r','\n'}, 20, 0);
}
