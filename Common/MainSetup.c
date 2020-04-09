	setlocale(LC_ALL, "C");
	openlog(AEM_LOGNAME, LOG_PID, LOG_MAIL);
	setlogmask(LOG_UPTO(LOG_INFO));

	if (argc != 1 || argv == NULL) {syslog(LOG_ERR, "Terminating: Invalid arguments"); return EXIT_FAILURE;}
	if (getuid() == 0 || getgid() == 0) {syslog(LOG_ERR, "Terminating: Must not be started as root"); return EXIT_FAILURE;}
	if (setSignals()  != 0) {syslog(LOG_ERR, "Terminating: Failed setting up signal handling"); return EXIT_FAILURE;}
	if (sodium_init() != 0) {syslog(LOG_ERR, "Terminating: Failed initializing libsodium"); return EXIT_FAILURE;}
