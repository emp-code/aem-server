#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "respond.h"

#include "../Common/AcceptClients.h"

#include "../Global.h"

#define AEM_LOGNAME "AEM-Web"

#include "../Common/Main_Include.c"

int main(void) {
#include "../Common/Main_Setup.c"

	if (tlsSetup() != 0) return EXIT_FAILURE;

	acceptClients();

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
