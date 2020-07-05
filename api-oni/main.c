#include <arpa/inet.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/SetCaps.h"
#include "../api-common/post.h"
#include "../api-common/SendMail.h"

#include "http.h"

#define AEM_API
#define AEM_API_ONI
#define AEM_LOGNAME "AEM-AOn"
#define AEM_PORT AEM_PORT_API_ONI
#define AEM_BACKLOG 25

#define AEM_MAXLEN_PIPEREAD 8192
#define AEM_MINLEN_PIPEREAD 128

#define AEM_SOCKET_TIMEOUT 15

static bool terminate = false;

static void sigTerm(const int sig) {
	terminate = true;

	if (sig == SIGUSR1) {
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	// SIGUSR2: Fast kill
	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"
#include "../Common/main_common.c"
#include "../Common/PipeLoad.c"

__attribute__((warn_unused_result))
static int pipeLoadPids(const int fd) {
	pid_t pid;

	if (read(fd, &pid, sizeof(pid_t)) != sizeof(pid_t)) return -1;
	setAccountPid(pid);

	if (read(fd, &pid, sizeof(pid_t)) != sizeof(pid_t)) return -1;
	setStoragePid(pid);

	if (read(fd, &pid, sizeof(pid_t)) != sizeof(pid_t)) return -1;
	setEnquiryPid(pid);

	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoadKeys(const int fd) {
	unsigned char buf[AEM_MAXLEN_PIPEREAD];

	if (read(fd, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_KEY_API) return -1;
	setApiKey(buf);

	if (read(fd, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_KEY_SIG) return -1;
	setSigKey(buf);

	if (read(fd, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_KEY_DKI) return -1;
	setDkimAdm(buf);

	if (read(fd, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_KEY_DKI) return -1;
	setDkimUsr(buf);

	if (read(fd, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_ACCESSKEY) return -1;
	setAccessKey_account(buf);

	if (read(fd, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_ACCESSKEY) return -1;
	setAccessKey_storage(buf);

	if (read(fd, buf, AEM_MAXLEN_PIPEREAD) != AEM_LEN_ACCESSKEY) return -1;
	setAccessKey_enquiry(buf);

	sodium_memzero(buf, AEM_MAXLEN_PIPEREAD);
	return 0;
}

int main(int argc, char *argv[]) {
#include "../Common/MainSetup.c"
	if (setCaps(CAP_NET_BIND_SERVICE) != 0) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	if (pipeLoadPids(argv[0][0]) < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears pids: %m"); return EXIT_FAILURE;}
	if (pipeLoadKeys(argv[0][0]) < 0) {syslog(LOG_ERR, "Terminating: Failed loading All-Ears keys: %m"); return EXIT_FAILURE;}
	close(argv[0][0]);

	if (aem_api_init() == 0) {
		acceptClients();
		aem_api_free();
	} else syslog(LOG_ERR, "Terminating: Failed initializing API");

	return EXIT_SUCCESS;
}
