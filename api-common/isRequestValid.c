#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/memeq.h"
#include "../Data/domain.h"

#include "isRequestValid.h"

#ifdef AEM_IS_ONION
#define AEM_MINLEN_POST 117 // POST /api HTTP/1.1\r\nHost: gt2wj6tc4b9wr21q3sjvro2jfem1j7cf00626cz4t1bksflt8kjqgjf8.onion:302\r\nContent-Length: 123\r\n\r\n
#else
#define AEM_MINLEN_POST 59 // POST /api HTTP/1.1\r\nHost: a.bc:302\r\nContent-Length: 123\r\n\r\n
#endif

__attribute__((warn_unused_result))
bool isRequestValid(const char * const req, const size_t lenReq, bool * const keepAlive, long * const clen) {
	if (lenReq < AEM_MINLEN_POST) return false;
	if (!memeq(req, "POST /api HTTP/1.1\r\n", 20)) return false;
	if (strcasestr(req, "\r\nConnection: close") != NULL) *keepAlive = false;

	const char * const host = strstr(req, "\r\nHost: ");
#ifdef AEM_IS_ONION
	if (host == NULL || !memeq(host + 8, AEM_ONIONID".onion:302\r\n", 68)) return false;
#else
	if (host == NULL || !memeq(host + 8, AEM_DOMAIN":302\r\n", AEM_DOMAIN_LEN + 6)) return false;
#endif

	const char * const clenStr = strstr(req, "\r\nContent-Length: ");
	if (clenStr == NULL) return false;
	*clen = strtol(clenStr + 18, NULL, 10);
	if (*clen <= (AEM_API_SEALBOX_SIZE + crypto_box_MACBYTES) || *clen > (AEM_API_SEALBOX_SIZE + crypto_box_MACBYTES + AEM_API_BOX_SIZE_MAX)) return false;

	// Forbidden request headers
	if (
		   NULL != strcasestr(req, "\r\nAuthorization:")
		|| NULL != strcasestr(req, "\r\nCookie:")
		|| NULL != strcasestr(req, "\r\nExpect:")
		|| NULL != strcasestr(req, "\r\nHTTP2-Settings:")
		|| NULL != strcasestr(req, "\r\nIf-Match:")
		|| NULL != strcasestr(req, "\r\nIf-Modified-Since:")
		|| NULL != strcasestr(req, "\r\nIf-None-Match:")
		|| NULL != strcasestr(req, "\r\nIf-Range:")
		|| NULL != strcasestr(req, "\r\nIf-Unmodified-Since:")
		|| NULL != strcasestr(req, "\r\nRange:")
		|| NULL != strcasestr(req, "\r\nReferer:")
		|| NULL != strcasestr(req, "\r\nSec-Fetch-Site: none")
		|| NULL != strcasestr(req, "\r\nSec-Fetch-Site: same-origin")
		// These are only for preflighted requests, which All-Ears doesn't use
		|| NULL != strcasestr(req, "\r\nAccess-Control-Request-Method:")
		|| NULL != strcasestr(req, "\r\nAccess-Control-Request-Headers:")
	) return false;

	const char *s = strcasestr(req, "\r\nAccept: ");
	if (s != NULL && !memeq(s + 10, "\r\n", 2)) return false;

	s = strcasestr(req, "\r\nAccept-Language: ");
	if (s != NULL && !memeq(s + 19, "\r\n", 2)) return false;

	s = strcasestr(req, "\r\nSec-Fetch-Dest: ");
	if (s != NULL && !memeq_anycase(s + 18, "empty\r\n", 7)) return false;

	s = strcasestr(req, "\r\nSec-Fetch-Mode: ");
	if (s != NULL && !memeq_anycase(s + 18, "cors\r\n", 6)) return false;

	return true;
}
