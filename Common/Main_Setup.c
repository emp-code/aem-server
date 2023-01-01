	if ( // Exit and unmount the chroot
	   fchdir(AEM_FD_ROOT) != 0
	|| close(AEM_FD_ROOT) != 0
	|| chroot(".") != 0 // Undo Manager's chroot
	|| chdir("/") != 0
	|| umount2("/old_root", MNT_DETACH | UMOUNT_NOFOLLOW) != 0
	) {syslog(LOG_ERR, "Terminating: Failed unmount: %m"); return EXIT_FAILURE;}

	setlocale(LC_ALL, "C");
	openlog(AEM_LOGNAME, LOG_PID, LOG_MAIL);
	setlogmask(LOG_UPTO(LOG_INFO));

	if (getuid() == 0 || getgid() == 0) {syslog(LOG_ERR, "Terminating: Must not be started as root"); return EXIT_FAILURE;}
	if (setSignals() != 0) {syslog(LOG_ERR, "Terminating: Failed setting up signal handling"); return EXIT_FAILURE;}
	if (setRlimits() != 0) {syslog(LOG_ERR, "Terminating: Failed settings rlimits"); return EXIT_FAILURE;}
	if (prctl(PR_SET_PDEATHSIG, SIGUSR2, 0, 0, 0) != 0) {syslog(LOG_ERR, "Failed prctl 1"); return EXIT_FAILURE;}
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)        != 0) {syslog(LOG_ERR, "Failed prctl 2"); return EXIT_FAILURE;} // Disable core dumps and ptrace

#ifdef AEM_WEB
	close(AEM_FD_PIPE_RD);
#else
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {syslog(LOG_ERR, "Terminating: Failed locking memory"); return EXIT_FAILURE;}
	if (sodium_init() != 0) {syslog(LOG_ERR, "Terminating: Failed sodium_init()"); return EXIT_FAILURE;}
#endif

#if defined(AEM_ACCOUNT) || defined(AEM_DELIVER) || defined(AEM_ENQUIRY) || defined(AEM_STORAGE)
	if (setCaps(0) != 0) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}
#endif
