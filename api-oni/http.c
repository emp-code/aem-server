#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>

#define AEM_MAXLEN_REQ 550

#include "../Data/domain.h"
#include "../Global.h"
#include "../api-common/isRequestValid.h"
#include "../api-common/post.h"

#include "http.h"

void respondClient(const int sock) {
	unsigned char buf[AEM_MAXLEN_REQ];
	unsigned char * const box = sodium_malloc(AEM_API_BOX_SIZE_MAX + crypto_box_MACBYTES);
	if (box == NULL) {syslog(LOG_ERR, "Failed sodium_malloc()"); return;}

	while(1) {
		int ret = recv(sock, buf, AEM_MAXLEN_REQ, 0);
		if (ret < 1) break;

		unsigned char * const postBegin = memmem(buf, ret, "\r\n\r\n", 4);
		if (postBegin == NULL) break;
		postBegin[3] = '\0';

		long clen = 0;
		bool keepAlive = true;
		if (!isRequestValid((char*)buf, ret, &keepAlive, &clen)) break;

		size_t lenPost = ret - ((postBegin + 4) - buf);
		if (lenPost > 0) memmove(buf, postBegin + 4, lenPost);

		if (lenPost < AEM_API_SEALBOX_SIZE) {
			ret = recv(sock, buf + lenPost, AEM_API_SEALBOX_SIZE - lenPost, 0);
			if (ret < 1) break;
			lenPost += ret;
		}
		if (lenPost < AEM_API_SEALBOX_SIZE) break;

		if (aem_api_prepare(buf, keepAlive) != 0) break;

		// Request is valid
		const size_t lenBox = clen - AEM_API_SEALBOX_SIZE;

		if (lenPost > AEM_API_SEALBOX_SIZE) {
			memcpy(box, buf + AEM_API_SEALBOX_SIZE, lenPost - AEM_API_SEALBOX_SIZE);
			lenPost -= AEM_API_SEALBOX_SIZE;
		} else lenPost = 0;

		while (lenPost < lenBox) {
			ret = recv(sock, box + lenPost, lenBox - lenPost, 0);
			if (ret < 1) break;
			lenPost += ret;
		}

		unsigned char *resp;
		const int lenResp = aem_api_process(box, lenBox, &resp);

		sodium_memzero(buf, AEM_MAXLEN_REQ);
		sodium_memzero(box, lenBox);

		if (lenResp < 0) break;
		send(sock, resp, lenResp, 0);
		sodium_memzero(resp, lenResp);

		if (!keepAlive) break;
	}

	sodium_free(box);
}
