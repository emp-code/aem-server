	if ( // Exit and unmount the chroot
	   fchdir(0) != 0 // 0 = fd to pivoted root
	|| close(0) != 0
	|| chroot(".") != 0 // Undo Manager's chroot
	|| chdir("/") != 0
	|| umount2("/old_root", MNT_DETACH) != 0
	) {syslog(LOG_ERR, "Terminating: Failed unmount: %m"); return EXIT_FAILURE;}

	setlocale(LC_ALL, "C");
	openlog(AEM_LOGNAME, LOG_PID, LOG_MAIL);
	setlogmask(LOG_UPTO(LOG_INFO));

#ifndef AEM_WEB
	if (sodium_init() != 0) {syslog(LOG_ERR, "Terminating: Failed sodium_init()"); return EXIT_FAILURE;}
#endif
	if (getuid() == 0 || getgid() == 0) {syslog(LOG_ERR, "Terminating: Must not be started as root"); return EXIT_FAILURE;}
	if (setSignals() != 0) {syslog(LOG_ERR, "Terminating: Failed setting up signal handling"); return EXIT_FAILURE;}
	if (setRlimits() != 0) {syslog(LOG_ERR, "Terminating: Failed settings rlimits"); return EXIT_FAILURE;}
