#include <syslog.h>
#include <unistd.h>

#include <wolfssl/ssl.h>

#include "../Common/AcceptClients.h"
#include "../Common/CreateSocket.h"
#include "../Common/x509_getCn.h"
#include "../IntCom/Client.h"

#include "MessageId.h"
#include "Request.h"
#include "SendMail.h"
#include "post.h"

#define AEM_LOGNAME "AEM-API"

#include "../Common/Main_Include.c"
#include "../Common/PipeRead.c"

__attribute__((warn_unused_result))
static int pipeLoad(void) {
	pid_t pids[3];
	unsigned char baseKey[AEM_KDF_SUB_KEYLEN];
	struct intcom_keyBundle bundle;

	size_t lenTlsCrt;
	size_t lenTlsKey;
	unsigned char tlsCrt[8192];
	unsigned char tlsKey[PIPE_BUF];
	unsigned char udsId;

	if (
	   pipeReadSmall(pids, sizeof(pid_t) * 2) != 0
	|| pipeReadSmall(baseKey, AEM_KDF_SUB_KEYLEN) != 0
	|| pipeReadSmall(&bundle, sizeof(bundle)) != 0
	|| pipeReadLarge(tlsCrt, &lenTlsCrt) != 0
	|| pipeReadLarge(tlsKey, &lenTlsKey) != 0
	|| pipeReadSmall(&udsId, 1) != 0
	) {close(AEM_FD_PIPE_RD); return -1;}
	close(AEM_FD_PIPE_RD);

	setAccountPid(pids[0]);
	setStoragePid(pids[1]);
	setEnquiryPid(pids[2]);

	setMsgIdKey(baseKey);
	sodium_memzero(baseKey, AEM_KDF_SUB_KEYLEN);

	intcom_setKeys_client(bundle.client);
	sodium_memzero(&bundle, sizeof(bundle));

	unsigned char domain[AEM_MAXLEN_OURDOMAIN];
	size_t lenDomain;
	x509_getSubject(domain, &lenDomain, tlsCrt, lenTlsCrt);

	setOurDomain(domain, lenDomain);

	int ret = sendMail_tls_init(tlsCrt, lenTlsCrt, tlsKey, lenTlsKey, domain, lenDomain);

	sodium_memzero(tlsCrt, lenTlsCrt);
	sodium_memzero(tlsKey, lenTlsKey);

	setUdsId(udsId);
	return ret;
}

int main(void) {
#include "../Common/Main_Setup.c"

	wolfSSL_Init();
	if (pipeLoad() < 0) return EXIT_FAILURE;

	acceptClients();

	sendMail_tls_free();

	wolfSSL_Cleanup();
	delMsgIdKey();
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
