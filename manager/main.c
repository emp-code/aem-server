#include <ctype.h> // for isxdigit
#include <errno.h>
#include <fcntl.h>
#include <linux/securebits.h>
#include <locale.h> // for setlocale
#include <sched.h> // for unshare
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h> // for mlockall
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/ToggleEcho.h"
#include "mount.h"

#include "manager.h"

static int getKey(void) {
	toggleEcho(false);

	puts("Enter Master Key (hex) - will not echo");

	char masterHex[crypto_secretbox_KEYBYTES * 2];
	for (unsigned int i = 0; i < crypto_secretbox_KEYBYTES * 2; i++) {
		const int gc = getchar_unlocked();
		if (gc == EOF || !isxdigit(gc)) {toggleEcho(true); return -1;}
		masterHex[i] = gc;
	}

	toggleEcho(true);

	unsigned char master[crypto_secretbox_KEYBYTES];
	sodium_hex2bin(master, crypto_secretbox_KEYBYTES, masterHex, crypto_secretbox_KEYBYTES * 2, NULL, NULL, NULL);
	sodium_memzero(masterHex, crypto_secretbox_KEYBYTES);
	setMasterKey(master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);
	return 0;
}

static int dropBounds(void) {
	return (
	   cap_drop_bound(CAP_AUDIT_CONTROL)    == 0
	&& cap_drop_bound(CAP_AUDIT_READ)       == 0
	&& cap_drop_bound(CAP_AUDIT_WRITE)      == 0
	&& cap_drop_bound(CAP_BLOCK_SUSPEND)    == 0
	&& cap_drop_bound(CAP_CHOWN)            == 0
	&& cap_drop_bound(CAP_DAC_OVERRIDE)     == 0
	&& cap_drop_bound(CAP_DAC_READ_SEARCH)  == 0
	&& cap_drop_bound(CAP_FOWNER)           == 0
	&& cap_drop_bound(CAP_FSETID)           == 0
	&& cap_drop_bound(CAP_IPC_LOCK)         == 0
	&& cap_drop_bound(CAP_IPC_OWNER)        == 0
	&& cap_drop_bound(CAP_KILL)             == 0
	&& cap_drop_bound(CAP_LEASE)            == 0
	&& cap_drop_bound(CAP_LINUX_IMMUTABLE)  == 0
	&& cap_drop_bound(CAP_MAC_ADMIN)        == 0
	&& cap_drop_bound(CAP_MAC_OVERRIDE)     == 0
	&& cap_drop_bound(CAP_MKNOD)            == 0
	&& cap_drop_bound(CAP_NET_ADMIN)        == 0
	&& cap_drop_bound(CAP_NET_BIND_SERVICE) == 0
	&& cap_drop_bound(CAP_NET_BROADCAST)    == 0
	&& cap_drop_bound(CAP_NET_RAW)          == 0
	&& cap_drop_bound(CAP_SETFCAP)          == 0
	&& cap_drop_bound(CAP_SETGID)           == 0
	&& cap_drop_bound(CAP_SETPCAP)          == 0
	&& cap_drop_bound(CAP_SETUID)           == 0
	&& cap_drop_bound(CAP_SYSLOG)           == 0
	&& cap_drop_bound(CAP_SYS_ADMIN)        == 0
	&& cap_drop_bound(CAP_SYS_BOOT)         == 0
	&& cap_drop_bound(CAP_SYS_CHROOT)       == 0
	&& cap_drop_bound(CAP_SYS_MODULE)       == 0
	&& cap_drop_bound(CAP_SYS_NICE)         == 0
	&& cap_drop_bound(CAP_SYS_PACCT)        == 0
	&& cap_drop_bound(CAP_SYS_PTRACE)       == 0
	&& cap_drop_bound(CAP_SYS_RAWIO)        == 0
	&& cap_drop_bound(CAP_SYS_RESOURCE)     == 0
	&& cap_drop_bound(CAP_SYS_TIME)         == 0
	&& cap_drop_bound(CAP_SYS_TTY_CONFIG)   == 0
	&& cap_drop_bound(CAP_WAKE_ALARM)       == 0
	) ? 0 : -1;
}

static int setCaps(void) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	const cap_value_t capMain[16] = {
		CAP_CHOWN, // Allow chown on any file
		CAP_DAC_OVERRIDE, // Bypass file permission checks
		CAP_DAC_READ_SEARCH, // Bypass file permission checks
		CAP_FOWNER, // Bypass file ownership checks
		CAP_IPC_LOCK, // mlockall()
		CAP_KILL, // Kill any process
		CAP_MKNOD, // Make special files
		CAP_NET_BIND_SERVICE, // Bind to port #<1024
		CAP_NET_RAW, // Bind to specific interfaces
		CAP_SETGID, // Set group IDs
		CAP_SETPCAP, // Allow capability/secbit changes
		CAP_SETUID, // Set user ID
		CAP_SYS_ADMIN, // Various, including mount()
		CAP_SYS_CHROOT, // Allow chroot
		CAP_SYS_NICE, // Allow raising process priorities
		CAP_SYS_RESOURCE // Allow changing resource limits
	};

	const cap_value_t capInherit[6] = {
		CAP_IPC_LOCK,
		CAP_NET_BIND_SERVICE,
		CAP_NET_RAW,
		CAP_SETPCAP,
		CAP_SYS_ADMIN,
		CAP_SYS_CHROOT
	};

	cap_t caps = cap_get_proc();

	return (
	   cap_clear(caps) == 0
	&& cap_set_flag(caps, CAP_INHERITABLE, 6, capInherit, CAP_SET) == 0
	&& cap_set_flag(caps, CAP_PERMITTED, 16, capMain, CAP_SET) == 0
	&& cap_set_flag(caps, CAP_EFFECTIVE, 16, capMain, CAP_SET) == 0
	&& cap_set_proc(caps) == 0
	&& cap_free(caps) == 0
	&& prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NOROOT | SECURE_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED) == 0
	) ? 0 : -1;
}

static int setLimits(void) {
	struct rlimit rlim;
	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;

	return (
	   setrlimit(RLIMIT_CORE,     &rlim) == 0
	|| setrlimit(RLIMIT_MSGQUEUE, &rlim) == 0
	) ? 0 : -1;
}

static bool ptraceDisabled(void) {
	const int fd = open("/proc/sys/kernel/yama/ptrace_scope", O_RDWR | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 1) return false;

	char val;
	if (read(fd, &val, 1) != 1) {close(fd); return false;}

	if (val != '3') {
		val = '3';
		if (
		   pwrite(fd, &val, 1, 0) != 1
		|| pread(fd, &val, 1, 0) != 1
		)  {close(fd); return false;}
	}

	close(fd);
	return (val == '3');
}

static int setSignals(void) {
	struct sigaction sa;
	sa.sa_handler = killAll;
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

static int setCgroup(void) {
	if (umount2(AEM_PATH_HOME"/cgroup", UMOUNT_NOFOLLOW) != 0 && errno != EINVAL) {printf("Failed cgroup2 unmount: %m\n"); return -1;}
	if (mount(NULL, AEM_PATH_HOME"/cgroup", "cgroup2", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, "") != 0) {printf("Failed cgroup2 mount: %m\n"); return -1;}

	const int fdDir = open(AEM_PATH_HOME"/cgroup", O_CLOEXEC | O_DIRECTORY | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_PATH);
	if (fdDir < 0) {printf("Failed opening /sys/fs/cgroup: %m\n"); return -1;}

	if (mkdirat(fdDir, "_aem", 0755) != 0 && errno != EEXIST) {syslog(LOG_ERR, "Failed creating _aem: %m"); close(fdDir); return -1;}
	const int fdAem = openat(fdDir, "_aem", O_CLOEXEC | O_DIRECTORY | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_PATH);
	close(fdDir);
	if (fdAem < 0) {syslog(LOG_ERR, "Failed opening _aem: %m"); return -1;}

	// Enable pids controller, create limited cgroup
	int fdFile = openat(fdAem, "cgroup.subtree_control", O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_WRONLY);
	if (write(fdFile, "+pids", 5) != 5) {printf("Failed writing to cgroup.subtree_control: %m\n"); close(fdAem); close(fdFile); return -1;}
	close(fdFile);

	if (mkdirat(fdAem, "limited", 0755) != 0 && errno != EEXIST) {syslog(LOG_ERR, "Failed creating _aem/limited: %m"); return -1;}

	fdFile = openat(fdAem, "limited/cgroup.subtree_control", O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_WRONLY);
	if (fdFile < 0) {syslog(LOG_ERR, "Failed opening cgroup.subtree_control: %m"); return -1;}
	if (write(fdFile, "+pids", 5) != 5) {printf("Failed writing to cgroup.subtree_control: %m\n"); close(fdAem); close(fdFile); return -1;}
	close(fdFile);

	fdFile = openat(fdAem, "limited/cgroup.type", O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_WRONLY);
	if (fdFile < 0) {syslog(LOG_ERR, "Failed opening cgroup.type: %m"); return -1;}
	if (write(fdFile, "threaded", 8) != 8) {printf("Failed writing to cgroup.type: %m\n"); close(fdAem); close(fdFile); return -1;}
	close(fdFile);

	fdFile = openat(fdAem, "limited/pids.max", O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_WRONLY);
	if (fdFile < 0) {syslog(LOG_ERR, "Failed opening pids.max: %m"); return -1;}
	if (write(fdFile, "0", 1) != 1) {printf("Failed writing to pids.max: %m\n"); close(fdAem); close(fdFile); return -1;}
	close(fdFile);

	// Put Manager into the root of the _aem group
	char pid_txt[32];
	sprintf(pid_txt, "%d", getpid());

	fdFile = openat(fdAem, "cgroup.procs", O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_WRONLY);
	if (fdFile < 0) {printf("Failed opening cgroup.procs: %m\n"); close(fdAem); return -1;}
	if (write(fdFile, pid_txt, strlen(pid_txt)) != (ssize_t)strlen(pid_txt)) {printf("Failed writing to cgroup.procs: %m\n"); close(fdAem); close(fdFile); return -1;}

	close(fdAem);
	close(fdFile);
	return 0;
}

int main(void) {
	setlocale(LC_ALL, "C");
	openlog("AEM-Man", LOG_PID, LOG_MAIL);

	if (getuid() != 0) {puts("Terminating: Must be started as root"); return 1;}
	if (!ptraceDisabled()) {puts("Terminating: Failed disabling ptrace"); return 2;}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 10;
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) return 11; // Disable core dumps and ptrace
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_EARLY, 0, 0, 0) != 0) return 12; // Kill early if memory corruption detected

	if (unshare(
		  CLONE_FILES // File descriptor table
		| CLONE_FS // chroot/chdir/umask (clone=reverse)
		| CLONE_NEWIPC // Unused
		| CLONE_NEWNS // Mount namespace
		| CLONE_NEWUTS // Hostname
		| CLONE_SYSVSEM // Unused
	) != 0) return 13;

	if (setpriority(PRIO_PROCESS, 0, -20)  != 0) return 14;
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) return 15;

	if (sodium_init() < 0) return 20;
	if (setCgroup()  != 0) return 21;
	if (setSignals() != 0) return 22;
	if (setLimits()  != 0) return 23;
	if (setCaps()    != 0) return 24;
	if (dropBounds() != 0) return 25;

	if (getKey() != 0) {puts("Terminating: Failed reading Master Key"); return 40;}
	if (loadFiles() != 0) {puts("Terminating: Failed reading files"); return 41;}

	puts("Ready");

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	receiveConnections();
	if (umount2(AEM_PATH_HOME"/cgroup", UMOUNT_NOFOLLOW) != 0 && errno != EINVAL) {printf("Failed cgroup2 unmount: %m\n"); return 50;}
	return 0;
}
