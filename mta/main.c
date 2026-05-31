#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../Common/AcceptClients.h"
#include "../Common/x509_getCn.h"
#include "../IntCom/Client.h"
#include "../IntCom/Stream_Client.h"

#include "respond.h"

#define AEM_LOGNAME "AEM-MTA"

#include "../Common/Main_Include.c"
#include "../Common/PipeRead.c"

__attribute__((warn_unused_result))
static int pipeLoad(void) {
	pid_t pids[2];
	struct intcom_keyBundle bundle;

	size_t lenTlsCrt;
	size_t lenTlsKey;
	unsigned char tlsCrt[8192];
	unsigned char tlsKey[PIPE_BUF];

	if (
	   pipeReadSmall(pids, sizeof(pid_t) * 2) != 0
	|| pipeReadSmall(&bundle, sizeof(bundle)) != 0
	|| pipeReadLarge(tlsCrt, &lenTlsCrt) != 0
	|| pipeReadLarge(tlsKey, &lenTlsKey) != 0
	) {close(AEM_FD_PIPE_RD); return -1;}
	close(AEM_FD_PIPE_RD);

	setAccountPid(pids[0]);
	intcom_setPid_stream(pids[1]);

	intcom_setKeys_client(bundle.client);
	intcom_setKey_stream(bundle.stream);
	sodium_memzero(&bundle, sizeof(bundle));

	unsigned char domain[AEM_MAXLEN_OURDOMAIN];
	size_t lenDomain;
	x509_getSubject(domain, &lenDomain, tlsCrt, lenTlsCrt);

	const int ret = tls_init(tlsCrt, lenTlsCrt, tlsKey, lenTlsKey, domain, lenDomain);

	sodium_memzero(tlsCrt, lenTlsCrt);
	sodium_memzero(tlsKey, lenTlsKey);
	if (ret != 0) syslog(LOG_ERR, "tls_init failed: %d", ret);
	return ret;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeLoad() != 0) return EXIT_FAILURE;

	acceptClients();

	syslog(LOG_INFO, "Terminating");
	tls_free();
	return EXIT_SUCCESS;
}
