#include <syslog.h>
#include <strings.h> // for bzero
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/AEM_KDF.h"
#include "../IntCom/Client.h"
#include "../IntCom/KeyBundle.h"
#include "../IntCom/Server.h"

#include "IO.h"

#define AEM_LOGNAME "AEM-Acc"

#include "../Common/Main_Include.c"

__attribute__((warn_unused_result))
static int setupIo(void) {
	pid_t storagePid;
	unsigned char baseKey[AEM_KDF_SUB_KEYLEN];
	struct intcom_keyBundle bundle;

	size_t lenRsaAdmin;
	size_t lenRsaUsers;
	unsigned char rsaAdmin[4096];
	unsigned char rsaUsers[4096];

	if (
	   read(AEM_FD_PIPE_RD, &storagePid, sizeof(pid_t)) != sizeof(pid_t)
	|| read(AEM_FD_PIPE_RD, baseKey, AEM_KDF_SUB_KEYLEN) != AEM_KDF_SUB_KEYLEN
	|| read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)
	|| read(AEM_FD_PIPE_RD, &lenRsaAdmin, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, rsaAdmin, lenRsaAdmin) != (ssize_t)lenRsaAdmin
	|| read(AEM_FD_PIPE_RD, &lenRsaUsers, sizeof(size_t)) != sizeof(size_t)
	|| read(AEM_FD_PIPE_RD, rsaUsers, lenRsaUsers) != (ssize_t)lenRsaUsers
	) {
		close(AEM_FD_PIPE_RD);
		syslog(LOG_ERR, "Terminating: Failed reading pipe");
		return -1;
	}
	close(AEM_FD_PIPE_RD);

	setStoragePid(storagePid);
	intcom_setKeys_server(bundle.server);
	intcom_setKeys_client(bundle.client);
	if (ioSetup(baseKey) != 0) {syslog(LOG_ERR, "Terminating: Failed setting up IO"); return -1;}
	setRsaKeys(rsaAdmin, lenRsaAdmin, rsaUsers, lenRsaUsers);

	sodium_memzero(baseKey, AEM_KDF_SUB_KEYLEN);
	sodium_memzero(&bundle, sizeof(bundle));
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	sleep(1);
	if (setupIo() != 0) return EXIT_FAILURE;

	syslog(LOG_INFO, "Ready");
	intcom_serve();

	ioFree();
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
