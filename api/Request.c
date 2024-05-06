#include <sys/socket.h>

#include <sodium.h>

#include "../Global.h"

#include "../Common/memeq.h"
#include "post.h"

#include "Request.h"

#define AEM_REQ_LINE1_LEN (6 + AEM_API_REQ_LEN_BASE64)

void respondClient(void) {
	unsigned char buf[AEM_REQ_LINE1_LEN];
	int ret = recv(AEM_FD_SOCK_CLIENT, buf, AEM_REQ_LINE1_LEN, 0);
	if (ret != AEM_REQ_LINE1_LEN) return;

	const bool post = memeq(buf, "POST /", 6);
	if (!post && !memeq(buf, "GET /", 5)) return;

	unsigned char req[AEM_API_REQ_LEN];
	size_t decodedLen = 0;
	sodium_base642bin(req, AEM_API_REQ_LEN, (const char*)buf + (post? 6 : 5), AEM_API_REQ_LEN_BASE64, NULL, &decodedLen, NULL, sodium_base64_VARIANT_URLSAFE);
	if (decodedLen != AEM_API_REQ_LEN) return;

	aem_api_process(req, post);
}
