#include <syslog.h>
#include <unistd.h>

#include <wolfssl/ssl.h>

#include "../Common/AcceptClients.h"
#include "../Common/x509_getCn.h"
#include "../IntCom/Client.h"

#include "MessageId.h"
#include "Request.h"
#include "SendMail.h"
#include "post.h"

#ifdef AEM_TLS
#define AEM_LOGNAME "AEM-API-Clr"
#include "ClientTLS.h"
#else
#define AEM_LOGNAME "AEM-API-Oni"
#endif

#include "../Common/Main_Include.c"

__attribute__((warn_unused_result))
static int pipeRead(void) {
	pid_t pids[3];
	struct intcom_keyBundle bundle;

	size_t lenTlsCrt;
	size_t lenTlsKey;
	unsigned char tlsCrt[PIPE_BUF];
	unsigned char tlsKey[PIPE_BUF];

	if (
	   read(AEM_FD_PIPE_RD, &pids, sizeof(pid_t) * 2) != sizeof(pid_t) * 2
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
	|| read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsCrt, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsCrt, lenTlsCrt) != (ssize_t)lenTlsCrt
	|| read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsKey, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsKey, lenTlsKey) != (ssize_t)lenTlsKey
	) {
		syslog(LOG_ERR, "Failed reading pipe: %m");
		close(AEM_FD_PIPE_RD);
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	setAccountPid(pids[0]);
	setStoragePid(pids[1]);
	setEnquiryPid(pids[2]);

	intcom_setKeys_client(bundle.client);
	sodium_memzero(&bundle, sizeof(bundle));

	unsigned char domain[AEM_MAXLEN_OURDOMAIN];
	size_t lenDomain;
	x509_getSubject(domain, &lenDomain, tlsCrt, lenTlsCrt);

	setOurDomain(domain, lenDomain);

	int ret = sendMail_tls_init(tlsCrt, lenTlsCrt, tlsKey, lenTlsKey, domain, lenDomain);
#ifdef AEM_TLS
	if (ret == 0) ret = tls_init(tlsCrt, lenTlsCrt, tlsKey, lenTlsKey, domain, lenDomain);
#endif

	sodium_memzero(tlsCrt, lenTlsCrt);
	sodium_memzero(tlsKey, lenTlsKey);

	return ret;
}

int main(void) {
#include "../Common/Main_Setup.c"

	wolfSSL_Init();
	if (pipeRead() < 0) {syslog(LOG_ERR, "Terminating: Failed pipeRead"); return EXIT_FAILURE;}

	acceptClients();

	sendMail_tls_free();
#ifdef AEM_TLS
	tls_free();
#endif

	wolfSSL_Cleanup();
	delMsgIdKey();
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
