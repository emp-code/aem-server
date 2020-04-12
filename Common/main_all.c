#include <sys/resource.h>

static int setSignals(void) {
	struct sigaction sa;
	sa.sa_handler = sigTerm;
	sigfillset(&(sa.sa_mask));
	sa.sa_flags = 0;

	return (
	   signal(SIGPIPE, SIG_IGN) != SIG_ERR
	&& signal(SIGCHLD, SIG_IGN) != SIG_ERR
	&& sigaction(SIGHUP,  &sa, NULL) != -1
	&& sigaction(SIGINT,  &sa, NULL) != -1
	&& sigaction(SIGQUIT, &sa, NULL) != -1
	&& sigaction(SIGTERM, &sa, NULL) != -1
	&& sigaction(SIGUSR1, &sa, NULL) != -1
	&& sigaction(SIGUSR2, &sa, NULL) != -1
	) ? 0 : -1;
}

static int setRlimits(void) {
	struct rlimit rlim;
	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;

	if (setrlimit(RLIMIT_NPROC, &rlim) != 0) return -1; // Forbid forking

	return 0;
}
