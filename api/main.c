#include <syslog.h>
#include <unistd.h>

#include "../Common/AcceptClients.h"
#include "../IntCom/Client.h"

#include "MessageId.h"
#include "Request.h"
#include "SendMail.h"
#include "post.h"

#define AEM_LOGNAME "AEM-API"

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

	tlsCrt[lenTlsCrt] = '\0';
	tlsKey[lenTlsKey] = '\0';
	lenTlsCrt++;
	lenTlsKey++;
	tlsSetup_sendmail(tlsCrt, lenTlsCrt, tlsKey, lenTlsKey);
	setOurDomain(tlsCrt, lenTlsCrt);

	sodium_memzero(tlsCrt, lenTlsCrt);
	sodium_memzero(tlsKey, lenTlsKey);
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeRead() < 0) {syslog(LOG_ERR, "Terminating: Failed pipeRead"); return EXIT_FAILURE;}

	acceptClients();

	tlsFree_sendmail();
	delMsgIdKey();
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
