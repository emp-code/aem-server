#include <ctype.h> // for isxdigit
#include <errno.h>
#include <fcntl.h>
#include <linux/securebits.h>
#include <locale.h> // for setlocale
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h> // for memlockall
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

#include "global.h"

#include "manager.h"

#define AEM_MODE_RO S_IRUSR | S_IRGRP
#define AEM_MODE_RW S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
#define AEM_MODE_RX S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP

static void toggleEcho(const bool on) {
	struct termios t;
	if (tcgetattr(STDIN_FILENO, &t) != 0) return;

	if (on) {
		t.c_lflag |= ((tcflag_t)ECHO);
		t.c_lflag |= ((tcflag_t)ICANON);
	} else {
		t.c_lflag &= ~((tcflag_t)ECHO);
		t.c_lflag &= ~((tcflag_t)ICANON);
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

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
		cap_drop_bound(CAP_AUDIT_CONTROL) == 0
	&& cap_drop_bound(CAP_AUDIT_READ) == 0
	&& cap_drop_bound(CAP_AUDIT_WRITE) == 0
	&& cap_drop_bound(CAP_BLOCK_SUSPEND) == 0
	&& cap_drop_bound(CAP_CHOWN) == 0
	&& cap_drop_bound(CAP_DAC_OVERRIDE) == 0
	&& cap_drop_bound(CAP_DAC_READ_SEARCH) == 0
	&& cap_drop_bound(CAP_FOWNER) == 0
	&& cap_drop_bound(CAP_FSETID) == 0
	&& cap_drop_bound(CAP_IPC_LOCK) == 0
	&& cap_drop_bound(CAP_IPC_OWNER) == 0
	&& cap_drop_bound(CAP_KILL) == 0
	&& cap_drop_bound(CAP_LEASE) == 0
	&& cap_drop_bound(CAP_LINUX_IMMUTABLE) == 0
	&& cap_drop_bound(CAP_MAC_ADMIN) == 0
	&& cap_drop_bound(CAP_MAC_OVERRIDE) == 0
	&& cap_drop_bound(CAP_MKNOD) == 0
	&& cap_drop_bound(CAP_NET_ADMIN) == 0
	&& cap_drop_bound(CAP_NET_BIND_SERVICE) == 0
	&& cap_drop_bound(CAP_NET_BROADCAST) == 0
	&& cap_drop_bound(CAP_NET_RAW) == 0
	&& cap_drop_bound(CAP_SETGID) == 0
	&& cap_drop_bound(CAP_SETFCAP) == 0
	&& cap_drop_bound(CAP_SETPCAP) == 0
	&& cap_drop_bound(CAP_SETUID) == 0
	&& cap_drop_bound(CAP_SYS_ADMIN) == 0
	&& cap_drop_bound(CAP_SYS_BOOT) == 0
	&& cap_drop_bound(CAP_SYS_CHROOT) == 0
	&& cap_drop_bound(CAP_SYS_MODULE) == 0
	&& cap_drop_bound(CAP_SYS_NICE) == 0
	&& cap_drop_bound(CAP_SYS_PACCT) == 0
	&& cap_drop_bound(CAP_SYS_PTRACE) == 0
	&& cap_drop_bound(CAP_SYS_RAWIO) == 0
	&& cap_drop_bound(CAP_SYS_RESOURCE) == 0
	&& cap_drop_bound(CAP_SYS_TIME) == 0
	&& cap_drop_bound(CAP_SYS_TTY_CONFIG) == 0
	&& cap_drop_bound(CAP_SYSLOG) == 0
	&& cap_drop_bound(CAP_WAKE_ALARM) == 0
	) ? 0 : -1;
}

static int setCaps() {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	const cap_value_t capInherit[] = {CAP_NET_BIND_SERVICE, CAP_SETPCAP};

	// To be trimmed when it's clearer which caps are needed
	const cap_value_t capMain[18] = {
		CAP_CHOWN,
		CAP_DAC_OVERRIDE,
		CAP_DAC_READ_SEARCH,
		CAP_FOWNER,
		CAP_FSETID,
		CAP_IPC_LOCK,
		CAP_IPC_OWNER,
		CAP_KILL,
		CAP_LEASE,
		CAP_MKNOD,
		CAP_NET_BIND_SERVICE,
		CAP_SETPCAP,
		CAP_SETGID,
		CAP_SETUID,
		CAP_SYS_ADMIN,
		CAP_SYS_CHROOT,
		CAP_SYS_NICE,
		CAP_SYS_RESOURCE
	};

	cap_t caps = cap_get_proc();

	return (
	   cap_clear(caps) == 0

	&& cap_set_flag(caps, CAP_PERMITTED, 18, capMain, CAP_SET) == 0
	&& cap_set_flag(caps, CAP_EFFECTIVE, 18, capMain, CAP_SET) == 0

	&& cap_set_flag(caps, CAP_INHERITABLE, 2, capInherit, CAP_SET) == 0

	&& cap_set_proc(caps) == 0
	&& cap_free(caps) == 0

	&& prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NOROOT | SECURE_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED) == 0
	) ? 0 : -1;
}

static int rxbind(const char * const source, const char * const target) {
	return (
	mount(source, target, NULL, MS_BIND, "") == 0 &&
	mount(NULL,   target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOATIME, NULL) == 0
	) ? 0 : -1;
}

static int rwbind(const char * const source, const char * const target) {
	return (
	mount(source, target, NULL, MS_BIND, "") == 0 &&
	mount(NULL,   target, NULL, MS_BIND | MS_REMOUNT | MS_NOEXEC | MS_NOSUID | MS_NODEV | MS_NOATIME, NULL) == 0
	) ? 0 : -1;
}

static int setMounts(void) {
	const struct passwd * const p = getpwnam("allears");
	gid_t allearsGroup = p->pw_gid;

	char tmpfs_opts[50];
	sprintf(tmpfs_opts, "uid=0,gid=%d,mode=0550,size=1,nr_inodes=50", allearsGroup);

	umask(0);

	return (
	   mkdir(AEM_CHROOT, 0) == 0
	&& mount("tmpfs", AEM_CHROOT, "tmpfs", MS_NOSUID | MS_NOATIME, tmpfs_opts) == 0

	&& mkdir(AEM_CHROOT"/usr",     AEM_MODE_RX) == 0
	&& mkdir(AEM_CHROOT"/usr/bin", AEM_MODE_RX) == 0
	&& mkdir(AEM_CHROOT"/dev",     AEM_MODE_RX) == 0
	&& lchown(AEM_CHROOT"/usr",     0, allearsGroup) == 0
	&& lchown(AEM_CHROOT"/usr/bin", 0, allearsGroup) == 0
	&& lchown(AEM_CHROOT"/dev",     0, allearsGroup) == 0

	&& mkdir(AEM_CHROOT"/lib",       0) == 0
	&& mkdir(AEM_CHROOT"/lib64",     0) == 0
	&& mkdir(AEM_CHROOT"/usr/lib",   0) == 0
	&& mkdir(AEM_CHROOT"/usr/lib64", 0) == 0

	&& rxbind("/lib",       AEM_CHROOT"/lib")       == 0
	&& rxbind("/lib64",     AEM_CHROOT"/lib64")     == 0
	&& rxbind("/usr/lib",   AEM_CHROOT"/usr/lib")   == 0
	&& rxbind("/usr/lib64", AEM_CHROOT"/usr/lib64") == 0

	&& mknod(AEM_CHROOT"/usr/bin/allears-api", S_IFREG, 0) == 0
	&& mknod(AEM_CHROOT"/usr/bin/allears-mta", S_IFREG, 0) == 0
	&& mknod(AEM_CHROOT"/usr/bin/allears-web", S_IFREG, 0) == 0
	&& rxbind("/usr/bin/allears/allears-api", AEM_CHROOT"/usr/bin/allears-api") == 0
	&& rxbind("/usr/bin/allears/allears-mta", AEM_CHROOT"/usr/bin/allears-mta") == 0
	&& rxbind("/usr/bin/allears/allears-web", AEM_CHROOT"/usr/bin/allears-web") == 0

	&& mknod(AEM_CHROOT"/dev/log", S_IFREG, 0) == 0
	&& rwbind("/dev/log", AEM_CHROOT"/dev/log") == 0

	&& mknod(AEM_CHROOT"/dev/null",    S_IFCHR | AEM_MODE_RW, makedev(1, 3)) == 0
	&& mknod(AEM_CHROOT"/dev/zero",    S_IFCHR | AEM_MODE_RW, makedev(1, 5)) == 0
	&& mknod(AEM_CHROOT"/dev/full",    S_IFCHR | AEM_MODE_RW, makedev(1, 7)) == 0
	&& mknod(AEM_CHROOT"/dev/random",  S_IFCHR | AEM_MODE_RW, makedev(1, 8)) == 0
	&& mknod(AEM_CHROOT"/dev/urandom", S_IFCHR | AEM_MODE_RW, makedev(1, 9)) == 0

	&& lchown(AEM_CHROOT"/dev/null",    0, allearsGroup) == 0
	&& lchown(AEM_CHROOT"/dev/zero",    0, allearsGroup) == 0
	&& lchown(AEM_CHROOT"/dev/full",    0, allearsGroup) == 0
	&& lchown(AEM_CHROOT"/dev/random",  0, allearsGroup) == 0
	&& lchown(AEM_CHROOT"/dev/urandom", 0, allearsGroup) == 0

	&& mount(NULL, AEM_CHROOT, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NOATIME, tmpfs_opts) == 0

	) ? 0 : -1;
}

static void unsetMounts(void) {
	// AEM_CHROOT
	umount(AEM_CHROOT"/usr/bin/allears-web");
	umount(AEM_CHROOT"/usr/bin/allears-api");
	umount(AEM_CHROOT"/usr/bin/allears-mta");
	umount(AEM_CHROOT"/lib");
	umount(AEM_CHROOT"/lib64");
	umount(AEM_CHROOT"/usr/lib");
	umount(AEM_CHROOT"/usr/lib64");
	umount(AEM_CHROOT"/dev/log");
	umount(AEM_CHROOT); // tmpfs, unmounting discards data
	rmdir(AEM_CHROOT);
}

static int setSignals(void) {
	return (

	   signal(SIGPIPE, SIG_IGN) != SIG_ERR
	&& signal(SIGCHLD, SIG_IGN) != SIG_ERR
	&& signal(SIGHUP,  SIG_IGN) != SIG_ERR

	&& signal(SIGINT,  killAll) != SIG_ERR
	&& signal(SIGQUIT, killAll) != SIG_ERR
	&& signal(SIGTERM, killAll) != SIG_ERR
	&& signal(SIGUSR1, killAll) != SIG_ERR
	&& signal(SIGUSR2, killAll) != SIG_ERR

	) ? 0 : -1;
}

static int setLimits() {
	struct rlimit rlim;
	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;

	if (setrlimit(RLIMIT_CORE, &rlim) != 0) return -1;
	if (setrlimit(RLIMIT_MSGQUEUE, &rlim) != 0) return -1;

	return 0;
}

int main(void) {
	setlocale(LC_ALL, "C");

	if (getuid() != 0) {puts("Terminating: Must be started as root"); return 1;}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 2;
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) return 3; // Disable core dumps
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_EARLY, 0, 0, 0) != 0) return 4; // Kill early if memory corruption detected

	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) return 5;
	if (sodium_init() < 0) return 6;
	if (setSignals() != 0) return 7;
	if (setLimits()  != 0) return 8;
	if (setCaps()    != 0) return 9;
	if (dropBounds() != 0) return 10;

	if (setMounts() != 0) {puts("Terminating: Failed to setup mounts"); return 11;}
	if (getKey()    != 0) {puts("Terminating: Failed reading Master Key"); return 12;}
	if (loadFiles() != 0) {puts("Terminating: Failed reading files"); return 13;}

	puts("Ready");

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	const int ret = receiveConnections();

	unsetMounts();
	return ret;
}
