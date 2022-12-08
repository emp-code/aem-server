#include <syslog.h>

#include "../Common/IntCom_Server.h"

#define AEM_LOGNAME "AEM-Enq"

#include "../Common/Main_Include.c"

int main(void) {
#include "../Common/Main_Setup.c"

	syslog(LOG_INFO, "Ready");
	takeConnections();

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
