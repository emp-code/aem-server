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
#include <syslog.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

#include "global.h"
#include "mount.h"

#include "manager.h"

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

static int setCaps(void) {
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

static int setLimits(void) {
	struct rlimit rlim;
	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;

	if (setrlimit(RLIMIT_CORE, &rlim) != 0) return -1;
	if (setrlimit(RLIMIT_MSGQUEUE, &rlim) != 0) return -1;

	return 0;
}

int main(void) {
	setlocale(LC_ALL, "C");
	openlog("AEM-Man", LOG_PID, LOG_MAIL);

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

	if (mkdir(AEM_CHROOT, 0) != 0) {printf("Terminating: %s exists\n", AEM_CHROOT); return 11;}
	if (getKey() != 0) {puts("Terminating: Failed reading Master Key"); return 12;}
	if (loadFiles() != 0) {puts("Terminating: Failed reading files"); return 13;}

	puts("Ready");

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	return receiveConnections();
}
