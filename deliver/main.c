#include <syslog.h>
#include <unistd.h>

#include "../Global.h"
#include "../Common/IntCom_Client.h" // for setting pids
#include "../Common/IntCom_Stream_Server.h"

#include "store.h"

#define AEM_LOGNAME "AEM-DLV"

#include "../Common/Main_Include.c"

__attribute__((warn_unused_result))
static int pipeLoadPids(void) {
	pid_t pids[2];
	if (read(AEM_FD_PIPE_RD, pids, sizeof(pid_t) * 2) != sizeof(pid_t) * 2) return -1;

	setEnquiryPid(pids[0]);
	setStoragePid(pids[1]);

	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadKeys(void) {
	unsigned char baseKey[crypto_kdf_KEYBYTES];
	if (read(AEM_FD_PIPE_RD, baseKey, crypto_kdf_KEYBYTES) != crypto_kdf_KEYBYTES) return -1;

	setSignKey(baseKey);
	sodium_memzero(baseKey, crypto_kdf_KEYBYTES);

	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeLoadPids() != 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids: %m"); return EXIT_FAILURE;}
	if (pipeLoadKeys() != 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears keys: %m"); return EXIT_FAILURE;}
	close(AEM_FD_PIPE_RD);

	syslog(LOG_INFO, "Ready");
	takeConnections();

	syslog(LOG_INFO, "Terminating");
	delSignKey();
	return EXIT_SUCCESS;
}
