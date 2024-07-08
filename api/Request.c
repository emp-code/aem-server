#include <sodium.h>

#include "../Global.h"

#include "../Common/memeq.h"
#include "post.h"

#ifdef AEM_TLS
#include "ClientTLS.h"
#else
#include <sys/socket.h>
#endif

#include "Request.h"

#define AEM_REQ_LINE1_LEN (6 + AEM_API_REQ_LEN_BASE64)

#ifdef AEM_TLS
#define AEM_RESPOND_FALSE false
#else
#define AEM_RESPOND_FALSE 
#endif

#ifdef AEM_TLS
bool
#else
void
#endif
	respondClient(void) {
	unsigned char buf[AEM_REQ_LINE1_LEN];

#ifdef AEM_TLS
	int ret = tls_recv(buf, AEM_REQ_LINE1_LEN);
#else
	int ret = recv(AEM_FD_SOCK_CLIENT, buf, AEM_REQ_LINE1_LEN, 0);
#endif

	if (ret != AEM_REQ_LINE1_LEN) return AEM_RESPOND_FALSE;

	const bool post = memeq(buf, "POST /", 6);
	if (!post && !memeq(buf, "GET /", 5)) return AEM_RESPOND_FALSE;

	unsigned char req[AEM_API_REQ_LEN];
	size_t decodedLen = 0;
	sodium_base642bin(req, AEM_API_REQ_LEN, (const char*)buf + (post? 6 : 5), AEM_API_REQ_LEN_BASE64, NULL, &decodedLen, NULL, sodium_base64_VARIANT_URLSAFE);
	if (decodedLen != AEM_API_REQ_LEN) return AEM_RESPOND_FALSE;

	aem_api_process(req, post);
#ifdef AEM_TLS
	return true;
#endif
}
