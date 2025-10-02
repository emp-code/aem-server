#include <syslog.h>
#include <unistd.h>

#ifdef AEM_TLS
#include <wolfssl/ssl.h>
#endif

#include "../Common/AcceptClients.h"
#include "../IntCom/Client.h"

#ifdef AEM_TLS
#define AEM_LOGNAME "AEM-Reg-Clr"
#include "ClientTLS.h"
#else
#define AEM_LOGNAME "AEM-Reg-Oni"
#endif

#include "respond.h"

#include "../Common/Main_Include.c"

__attribute__((warn_unused_result))
static int pipeRead(void) {
	pid_t accPid;
	struct intcom_keyBundle bundle;

#ifdef AEM_TLS
	size_t lenTlsCrt;
	size_t lenTlsKey;
	unsigned char tlsCrt[PIPE_BUF];
	unsigned char tlsKey[PIPE_BUF];
#endif

	if (
	   read(AEM_FD_PIPE_RD, &accPid, sizeof(pid_t)) != sizeof(pid_t)
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
#ifdef AEM_TLS
	|| read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsCrt, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsCrt, lenTlsCrt) != (ssize_t)lenTlsCrt
	|| read(AEM_FD_PIPE_RD, (unsigned char*)&lenTlsKey, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, tlsKey, lenTlsKey) != (ssize_t)lenTlsKey
#endif
	) {
		syslog(LOG_ERR, "Failed reading pipe: %m");
		close(AEM_FD_PIPE_RD);
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	setAccountPid(accPid);

	intcom_setKeys_client(bundle.client);
	sodium_memzero(&bundle, sizeof(bundle));

#ifdef AEM_TLS
	const int ret = tls_init(tlsCrt, lenTlsCrt, tlsKey, lenTlsKey, domain, lenDomain);
	sodium_memzero(tlsCrt, lenTlsCrt);
	sodium_memzero(tlsKey, lenTlsKey);
	return ret;
#endif

	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

#ifdef AEM_TLS
	wolfSSL_Init();
#endif

	if (pipeRead() < 0) {syslog(LOG_ERR, "Terminating: Failed pipeRead"); return EXIT_FAILURE;}
	acceptClients();

#ifdef AEM_TLS
	tls_free();
	wolfSSL_Cleanup();
#endif

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
