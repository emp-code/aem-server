static int setSignals(void) {
	struct sigaction sa;
#ifdef AEM_MANAGER
	sa.sa_handler = killAll;
#else
	sa.sa_handler = sigTerm;
#endif
	memset(&(sa.sa_mask), 0xFF, sizeof(sigset_t));
	sa.sa_flags = 0;

	return (
	   signal(SIGPIPE, SIG_IGN) != SIG_ERR
	&& signal(SIGCHLD, SIG_IGN) != SIG_ERR
#ifdef AEM_MANAGER
	&& signal(SIGHUP, SIG_IGN) != SIG_ERR
#else
	&& sigaction(SIGHUP,  &sa, NULL) != -1
#endif
	&& sigaction(SIGINT,  &sa, NULL) != -1
	&& sigaction(SIGQUIT, &sa, NULL) != -1
	&& sigaction(SIGTERM, &sa, NULL) != -1
	&& sigaction(SIGUSR1, &sa, NULL) != -1
	&& sigaction(SIGUSR2, &sa, NULL) != -1
	) ? 0 : -1;
}
