#include <syslog.h>
#include <unistd.h>

#include "../Common/AcceptClients.h"
#include "../IntCom/Client.h"

#include "MessageId.h"
#include "respond.h"
#include "post.h"

#ifdef AEM_API_CLR
#define AEM_LOGNAME "AEM-API"
#else
#define AEM_LOGNAME "AEM-AOn"
#endif

#include "../Common/Main_Include.c"

__attribute__((warn_unused_result))
static int pipeLoadPids(void) {
	pid_t pids[3];
	if (read(AEM_FD_PIPE_RD, pids, sizeof(pid_t) * 3) != sizeof(pid_t) * 3) return -1;

	setAccountPid(pids[0]);
	setStoragePid(pids[1]);
	setEnquiryPid(pids[2]);
	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadKeys(void) {
	unsigned char baseKey[crypto_kdf_KEYBYTES];
	struct intcom_keyBundle bundle;

	if (read(AEM_FD_PIPE_RD, baseKey, crypto_kdf_KEYBYTES) != crypto_kdf_KEYBYTES) return -1;
	if (read(AEM_FD_PIPE_RD, &bundle, sizeof(bundle)) != sizeof(bundle)) return -1;

	setApiKeys(baseKey);
	setMsgIdKey(baseKey);
	intcom_setKeys_client(bundle.client);

	sodium_memzero(baseKey, crypto_kdf_KEYBYTES);
	sodium_memzero(&bundle, sizeof(bundle));
	return 0;
}

int main(void) {
#include "../Common/Main_Setup.c"

	if (pipeLoadPids() < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids: %m"); return EXIT_FAILURE;}
	if (pipeLoadKeys() < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears keys: %m"); return EXIT_FAILURE;}
	close(AEM_FD_PIPE_RD);

#ifdef AEM_API_CLR
	if (tlsSetup() != 0) {syslog(LOG_ERR, "Terminating: Failed initializing TLS"); return EXIT_FAILURE;}
#endif
	if (aem_api_init() != 0) {syslog(LOG_ERR, "Terminating: Failed initializing API"); return EXIT_FAILURE;}

	acceptClients();

	aem_api_free();
	delMsgIdKey();
#ifdef AEM_API_CLR
	tlsFree();
#endif
	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
