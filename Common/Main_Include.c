#include <locale.h> // for setlocale
#include <signal.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/SetCaps.h"

static int setSignals(void) {
	struct sigaction sa;
	sa.sa_handler = sigTerm;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;

	return (
	   signal(SIGPIPE, SIG_IGN) != SIG_ERR
	&& signal(SIGCHLD, SIG_IGN) != SIG_ERR
	&& signal(SIGHUP,  SIG_IGN) != SIG_ERR
	&& sigaction(SIGINT,  &sa, NULL) != -1
	&& sigaction(SIGQUIT, &sa, NULL) != -1
	&& sigaction(SIGTERM, &sa, NULL) != -1
	&& sigaction(SIGUSR1, &sa, NULL) != -1
	&& sigaction(SIGUSR2, &sa, NULL) != -1
	) ? 0 : -1;
}
