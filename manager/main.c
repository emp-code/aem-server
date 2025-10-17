#include <ctype.h> // for isxdigit
#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <linux/securebits.h>
#include <locale.h> // for setlocale
#include <sched.h> // for unshare
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h> // for mlockall
#include <sys/mount.h>
#include <sys/prctl.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/ValidFd.h"

#include "manager.h"
#include "mount.h"

__attribute__((warn_unused_result))
static int dropBounds(void) {
	return (
	   cap_drop_bound(CAP_AUDIT_CONTROL)      == 0
	&& cap_drop_bound(CAP_AUDIT_READ)         == 0
	&& cap_drop_bound(CAP_AUDIT_WRITE)        == 0
	&& cap_drop_bound(CAP_BLOCK_SUSPEND)      == 0
	&& cap_drop_bound(CAP_BPF)                == 0
	&& cap_drop_bound(CAP_CHECKPOINT_RESTORE) == 0
	&& cap_drop_bound(CAP_CHOWN)              == 0
	&& cap_drop_bound(CAP_DAC_OVERRIDE)       == 0
	&& cap_drop_bound(CAP_DAC_READ_SEARCH)    == 0
	&& cap_drop_bound(CAP_FOWNER)             == 0
	&& cap_drop_bound(CAP_FSETID)             == 0
	&& cap_drop_bound(CAP_IPC_LOCK)           == 0
	&& cap_drop_bound(CAP_IPC_OWNER)          == 0
	&& cap_drop_bound(CAP_KILL)               == 0
	&& cap_drop_bound(CAP_LEASE)              == 0
	&& cap_drop_bound(CAP_LINUX_IMMUTABLE)    == 0
	&& cap_drop_bound(CAP_MAC_ADMIN)          == 0
	&& cap_drop_bound(CAP_MAC_OVERRIDE)       == 0
	&& cap_drop_bound(CAP_MKNOD)              == 0
	&& cap_drop_bound(CAP_NET_ADMIN)          == 0
	&& cap_drop_bound(CAP_NET_BIND_SERVICE)   == 0
	&& cap_drop_bound(CAP_NET_BROADCAST)      == 0
	&& cap_drop_bound(CAP_NET_RAW)            == 0
	&& cap_drop_bound(CAP_PERFMON)            == 0
	&& cap_drop_bound(CAP_SETFCAP)            == 0
	&& cap_drop_bound(CAP_SETGID)             == 0
	&& cap_drop_bound(CAP_SETPCAP)            == 0
	&& cap_drop_bound(CAP_SETUID)             == 0
	&& cap_drop_bound(CAP_SYSLOG)             == 0
	&& cap_drop_bound(CAP_SYS_ADMIN)          == 0
	&& cap_drop_bound(CAP_SYS_BOOT)           == 0
	&& cap_drop_bound(CAP_SYS_CHROOT)         == 0
	&& cap_drop_bound(CAP_SYS_MODULE)         == 0
	&& cap_drop_bound(CAP_SYS_NICE)           == 0
	&& cap_drop_bound(CAP_SYS_PACCT)          == 0
	&& cap_drop_bound(CAP_SYS_PTRACE)         == 0
	&& cap_drop_bound(CAP_SYS_RAWIO)          == 0
	&& cap_drop_bound(CAP_SYS_RESOURCE)       == 0
	&& cap_drop_bound(CAP_SYS_TIME)           == 0
	&& cap_drop_bound(CAP_SYS_TTY_CONFIG)     == 0
	&& cap_drop_bound(CAP_WAKE_ALARM)         == 0
	) ? 0 : -1;
}

__attribute__((warn_unused_result))
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

__attribute__((warn_unused_result))
static int setLimits(void) {
	struct rlimit rlim;
	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;

	return (
	   setrlimit(RLIMIT_CORE,     &rlim) == 0
	|| setrlimit(RLIMIT_MSGQUEUE, &rlim) == 0
	) ? 0 : -1;
}

__attribute__((warn_unused_result))
static bool ptraceDisabled(void) {
	const int fd = open("/proc/sys/kernel/yama/ptrace_scope", O_RDWR | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0 || !validFd(fd)) return false;

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

__attribute__((warn_unused_result))
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

__attribute__((warn_unused_result, nonnull))
static int writeFile(const int fdDir, const char * const path, const char * const data, const ssize_t lenData) {
	const int fdFile = openat(fdDir, path, O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_WRONLY);
	if (fdFile < 0 || !validFd(fdFile)) {printf("Failed opening file: %m\n"); return -1;}

	const ssize_t ret = write(fdFile, data, lenData);
	close(fdFile);
	return (ret == lenData) ? 0 : -1;
}

__attribute__((warn_unused_result))
static int setCgroup(void) {
	if (umount2(AEM_PATH_HOME"/cgroup", UMOUNT_NOFOLLOW) != 0 && errno != EINVAL) {printf("Failed cgroup2 unmount: %m\n"); return -1;}
	if (mount(NULL, AEM_PATH_HOME"/cgroup", "cgroup2", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, "") != 0) {printf("Failed cgroup2 mount: %m\n"); return -1;}

	const int fdDir = open(AEM_PATH_HOME"/cgroup", O_CLOEXEC | O_DIRECTORY | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_PATH);
	if (fdDir < 0) {printf("Failed opening /sys/fs/cgroup: %m\n"); return -1;}

	if (mkdirat(fdDir, "_aem", 0755) != 0 && errno != EEXIST) {printf("Failed creating _aem: %m\n"); close(fdDir); return -1;}
	const int fdAem = openat(fdDir, "_aem", O_CLOEXEC | O_DIRECTORY | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_PATH);
	close(fdDir);
	if (fdAem < 0) {printf("Failed opening _aem: %m\n"); return -1;}

	char pid_txt[32];
	sprintf(pid_txt, "%d", getpid());

	// Setup cgroups
	if ((mkdirat(fdAem, "limited", 0755) != 0 && errno != EEXIST)
	|| 0 != writeFile(fdAem, "cgroup.max.depth", "1", 1)
	|| 0 != writeFile(fdAem, "cgroup.max.descendants", "1", 1)
	|| 0 != writeFile(fdAem, "cgroup.subtree_control", "+pids", 5)
	|| 0 != writeFile(fdAem, "limited/cgroup.max.depth", "0", 1)
	|| 0 != writeFile(fdAem, "limited/cgroup.max.descendants", "0", 1)
	|| 0 != writeFile(fdAem, "limited/cgroup.subtree_control", "+pids", 5)
	|| 0 != writeFile(fdAem, "limited/cgroup.type", "threaded", 8)
	|| 0 != writeFile(fdAem, "limited/pids.max", "0", 1)
	|| 0 != writeFile(fdAem, "cgroup.procs", pid_txt, strlen(pid_txt))
	) {
		printf("Failed creating cgroup files: %m\n");
		close(fdAem);
		return -1;
	}

	close(fdAem);
	return 0;
}

__attribute__((warn_unused_result))
static int setupHome(void) {
	const struct passwd * const ae = getpwnam("allears");

	return (ae != NULL
	&& chmod(AEM_PATH_HOME"/Account.aem", S_IRUSR | S_IWUSR) == 0
	&& chmod(AEM_PATH_HOME"/Data", S_IRUSR | S_IWUSR | S_IXUSR) == 0
	&& chmod(AEM_PATH_HOME"/GeoLite2-ASN.mmdb", S_IRUSR | S_IWUSR | S_IRGRP) == 0
	&& chmod(AEM_PATH_HOME"/GeoLite2-Country.mmdb", S_IRUSR | S_IWUSR | S_IRGRP) == 0
	&& chmod(AEM_PATH_HOME"/Msg", S_IRUSR | S_IWUSR | S_IXUSR) == 0
	&& chmod(AEM_PATH_HOME"/Settings.aem", S_IRUSR | S_IWUSR) == 0
	&& chmod(AEM_PATH_HOME"/Stindex.aem", S_IRUSR | S_IWUSR) == 0
	&& chmod(AEM_PATH_HOME"/bin", S_IRUSR | S_IWUSR | S_IXUSR) == 0

	&& chown(AEM_PATH_HOME"/Account.aem", ae->pw_uid, ae->pw_gid) == 0
	&& chown(AEM_PATH_HOME"/Data", 0, 0) == 0
	&& chown(AEM_PATH_HOME"/GeoLite2-ASN.mmdb", 0, ae->pw_gid) == 0
	&& chown(AEM_PATH_HOME"/GeoLite2-Country.mmdb", 0, ae->pw_gid) == 0
	&& chown(AEM_PATH_HOME"/Msg", ae->pw_uid, ae->pw_gid) == 0
	&& chown(AEM_PATH_HOME"/Settings.aem", ae->pw_uid, ae->pw_gid) == 0
	&& chown(AEM_PATH_HOME"/Stindex.aem", ae->pw_uid, ae->pw_gid) == 0
	&& chown(AEM_PATH_HOME"/bin", 0, 0) == 0) ? 0 : -1;
}

int main(void) {
	setlocale(LC_ALL, "C");

	if (getuid() != 0) return 1;
	if (!ptraceDisabled()) return 2;
	if (setupHome() != 0) return 3;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)         != 0) return 4;
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)             != 0) return 5; // Disable core dumps and ptrace
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_EARLY, 0, 0, 0) != 0) return 6; // Kill early if memory corruption detected

	if (unshare(
		  CLONE_FILES // File descriptor table
		| CLONE_FS // chroot/chdir/umask (clone=reverse)
		| CLONE_NEWIPC // Unused
		| CLONE_NEWNS // Mount namespace
		| CLONE_NEWUTS // Hostname
		| CLONE_SYSVSEM // Unused
	) != 0) return 7;

	if (setpriority(PRIO_PROCESS, 0, -20)  != 0) return 8;
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) return 9;

	if (sodium_init() != 0) return 10;
	if (setCgroup()   != 0) return 11;
	if (setSignals()  != 0) return 12;
	if (setLimits()   != 0) return 13;
	if (setCaps()     != 0) return 14;
	if (dropBounds()  != 0) return 15;

	return setupManager();
}
