#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/sched.h>
#include <linux/securebits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // for bzero
#include <sys/capability.h>
#include <sys/mman.h> // for memfd_create()
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h> // for umask
#include <sys/syscall.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/CreateSocket.h"
#include "../Common/GetKey.h"
#include "../Common/ValidFd.h"
#include "../IntCom/KeyBundle.h"

#include "../Global.h"

#include "mount.h"

#include "manager.h"

#define AEM_FD_SERVER 0
#define AEM_FD_CLIENT 1

enum intcom_keynum {
	AEM_KEYNUM_INTCOM_NULL,
	AEM_KEYNUM_INTCOM_ACCOUNT_API,
	AEM_KEYNUM_INTCOM_ACCOUNT_MTA,
	AEM_KEYNUM_INTCOM_ENQUIRY_API,
	AEM_KEYNUM_INTCOM_ENQUIRY_DLV,
	AEM_KEYNUM_INTCOM_STORAGE_ACC,
	AEM_KEYNUM_INTCOM_STORAGE_API,
	AEM_KEYNUM_INTCOM_STORAGE_DLV,
	AEM_KEYNUM_INTCOM_STREAM
};

static unsigned char key_bin[crypto_secretbox_KEYBYTES];
static unsigned char key_mng[crypto_secretbox_KEYBYTES];
static unsigned char key_api[crypto_kdf_KEYBYTES];
static unsigned char key_ic[crypto_kdf_KEYBYTES];

static const int typeNice[AEM_PROCESSTYPES_COUNT] = AEM_NICE;

static pid_t pid_account = 0;
static pid_t pid_deliver = 0;
static pid_t pid_enquiry = 0;
static pid_t pid_storage = 0;
static pid_t aemPid[5][AEM_MAXPROCESSES];

static bool terminate = false;

static void wipeKeys(void) {
	sodium_memzero(key_mng, crypto_secretbox_KEYBYTES);
	sodium_memzero(key_api, crypto_kdf_KEYBYTES);
}

static bool process_exists(const pid_t pid) {
	return (pid < 1) ? false : kill(pid, 0) == 0;
}

static void refreshPids(void) {
	for (int type = 0; type < 5; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemPid[type][i] != 0 && !process_exists(aemPid[type][i])) {
				aemPid[type][i] = 0;
			}
		}
	}

	if (pid_account != 0 && !process_exists(pid_account)) pid_account = 0;
	if (pid_deliver != 0 && !process_exists(pid_deliver)) pid_deliver = 0;
	if (pid_enquiry != 0 && !process_exists(pid_enquiry)) pid_enquiry = 0;
	if (pid_storage != 0 && !process_exists(pid_storage)) pid_storage = 0;
}

// SIGUSR1 = Allow processing one more connection; SIGUSR2 = Immediate termination
void killAll(int sig) {
	wipeKeys();
	sodium_memzero(key_bin, crypto_secretbox_KEYBYTES);
	refreshPids();

	if (sig != SIGUSR1 && sig != SIGUSR2) sig = SIGUSR1;

	for (int type = 0; type < 3; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemPid[type][i] > 0) kill(aemPid[type][i], sig); // Request process to terminate
		}
	}

	if (sig == SIGUSR1) {
		// TODO: Connect to each service to make sure they'll terminate
	} else {
		if (pid_account > 0) kill(pid_account, SIGUSR2);
		if (pid_deliver > 0) kill(pid_deliver, SIGUSR2);
		if (pid_enquiry > 0) kill(pid_enquiry, SIGUSR2);
		if (pid_storage > 0) kill(pid_storage, SIGUSR2);
	}

	// Processes should have terminated after one second
	sleep(1);
	refreshPids();

	if (sig == SIGUSR1) {
		for (int type = 0; type < 3; type++) {
			for (int i = 0; i < AEM_MAXPROCESSES; i++) {
				if (aemPid[type][i] > 0) kill(aemPid[type][i], SIGUSR2);
			}
		}

		if (pid_account > 0) kill(pid_account, SIGUSR1);
		if (pid_deliver > 0) kill(pid_deliver, SIGUSR1);
		if (pid_enquiry > 0) kill(pid_enquiry, SIGUSR1);
		if (pid_storage > 0) kill(pid_storage, SIGUSR1);

		sleep(1);
		refreshPids();
	}

	for (int type = 0; type < 3; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemPid[type][i] > 0) kill(aemPid[type][i], SIGKILL);
		}
	}

	if (pid_account > 0) kill(pid_account, SIGUSR2);
	if (pid_deliver > 0) kill(pid_deliver, SIGUSR2);
	if (pid_enquiry > 0) kill(pid_enquiry, SIGUSR2);
	if (pid_storage > 0) kill(pid_storage, SIGUSR2);

	sleep(1);
	refreshPids();

	if (pid_account > 0) kill(pid_account, SIGKILL);
	if (pid_deliver > 0) kill(pid_deliver, SIGKILL);
	if (pid_enquiry > 0) kill(pid_enquiry, SIGKILL);
	if (pid_storage > 0) kill(pid_storage, SIGKILL);

	umount2(AEM_PATH_MOUNTDIR, MNT_DETACH);
	exit(EXIT_SUCCESS);
}

static int loadExec(const int type) {
	if (memfd_create("aem", MFD_CLOEXEC | MFD_ALLOW_SEALING) != AEM_FD_BINARY) {
		syslog(LOG_ERR, "Failed memfd_create: %m");
		return -1;
	}

	const char * const path[] = AEM_PATH_EXE;
	const int fd = open(path[type], O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0 || !validFd(fd)) {syslog(LOG_ERR, "Failed opening file: %s", path[type]); return -1;}

	const off_t bytes = lseek(fd, 0, SEEK_END);
	if (bytes < 1 || bytes > AEM_MAXSIZE_EXEC) {
		syslog(LOG_ERR, "Invalid length on %s", path[type]);
		close(fd);
		return -1;
	}

	unsigned char * const tmp = malloc(bytes);
	if (pread(fd, tmp, bytes, 0) != bytes) {
		syslog(LOG_ERR, "Failed reading %s: %m", path[type]);
		close(fd);
		free(tmp);
		return -1;
	}

	close(fd);

	if (crypto_secretbox_open_easy(tmp + crypto_secretbox_NONCEBYTES, tmp + crypto_secretbox_NONCEBYTES, bytes - crypto_secretbox_NONCEBYTES, tmp, key_bin) != 0) {
		syslog(LOG_ERR, "Failed decrypting %s", path[type]);
		free(tmp);
		return -1;
	}

	if (
	   write(AEM_FD_BINARY, tmp + crypto_secretbox_NONCEBYTES, bytes - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES) != bytes - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES
	|| fcntl(AEM_FD_BINARY, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0
	) {
		syslog(LOG_ERR, "Failed loadExec: %m");
		free(tmp);
		return -1;
	}

	free(tmp);
	return 0;
}

static int setCaps(const int type) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	// Ambient capabilities
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) return -1;

	cap_value_t cap[5];
	cap[0] = CAP_SYS_ADMIN;
	cap[1] = CAP_SYS_CHROOT;
	int numCaps;

	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT:
		case AEM_PROCESSTYPE_DELIVER:
		case AEM_PROCESSTYPE_ENQUIRY:
		case AEM_PROCESSTYPE_STORAGE:
			cap[2] = CAP_IPC_LOCK;
			numCaps = 3;
		break;

		case AEM_PROCESSTYPE_API_CLR:
		case AEM_PROCESSTYPE_API_ONI:
		case AEM_PROCESSTYPE_MTA:
			cap[2] = CAP_IPC_LOCK;
			cap[3] = CAP_NET_BIND_SERVICE;
			cap[4] = CAP_NET_RAW;
			numCaps = 5;
		break;

		case AEM_PROCESSTYPE_WEB_CLR:
		case AEM_PROCESSTYPE_WEB_ONI:
			cap[2] = CAP_NET_BIND_SERVICE;
			cap[3] = CAP_NET_RAW;
			numCaps = 4;
		break;

		default: return -1;
	}

	if (
	   prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap[0], 0, 0) != 0
	|| prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap[1], 0, 0) != 0
	|| prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap[2], 0, 0) != 0
	|| (numCaps > 3 && prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap[3], 0, 0) != 0)
	|| (numCaps > 4 && prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap[4], 0, 0) != 0)
	) return -1;

	// Allow changing SecureBits for the next part
	const cap_value_t capPcap = CAP_SETPCAP;
	cap_t caps = cap_get_proc();
	if (caps == NULL || cap_set_flag(caps, CAP_EFFECTIVE, 1, &capPcap, CAP_SET) != 0 || cap_set_proc(caps) != 0) return -1;

	// Disable and lock further ambient caps
	if (prctl(PR_SET_SECUREBITS, SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED | SECBIT_NOROOT | SECURE_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED) != 0) {
		syslog(LOG_ERR, "Failed setting SecureBits");
		return -1;
	}

	// Disable all but the capabilities needed
	return (
		cap_clear(caps) == 0
	&& cap_set_flag(caps, CAP_INHERITABLE, numCaps, cap, CAP_SET) == 0
	&& cap_set_flag(caps, CAP_PERMITTED,   numCaps, cap, CAP_SET) == 0
	&& cap_set_flag(caps, CAP_EFFECTIVE,   numCaps, cap, CAP_SET) == 0
	&& cap_set_proc(caps) == 0
	&& cap_free(caps) == 0
	) ? 0 : -1;
}

static int setLimits(const int type) {
	struct rlimit rlim;

	if (type != AEM_PROCESSTYPE_ACCOUNT && type != AEM_PROCESSTYPE_STORAGE) {
		rlim.rlim_cur = 0;
		rlim.rlim_max = 0;
		if (setrlimit(RLIMIT_FSIZE, &rlim) != 0) return -1;
	}

	switch (type) {
		case AEM_PROCESSTYPE_ENQUIRY: rlim.rlim_cur = 15; break;
		case AEM_PROCESSTYPE_STORAGE: rlim.rlim_cur = 5; break;

		case AEM_PROCESSTYPE_ACCOUNT:
		case AEM_PROCESSTYPE_DELIVER:
		case AEM_PROCESSTYPE_MTA:
		case AEM_PROCESSTYPE_WEB_CLR:
		case AEM_PROCESSTYPE_WEB_ONI:
		case AEM_PROCESSTYPE_API_CLR:
		case AEM_PROCESSTYPE_API_ONI: rlim.rlim_cur = 4; break;
	}

	rlim.rlim_max = rlim.rlim_cur;
	if (setrlimit(RLIMIT_OFILE, &rlim) != 0) return -1;

	rlim.rlim_cur = (typeNice[type] * -1) + 20; // The actual ceiling for the nice value is calculated as 20 - rlim_cur
	rlim.rlim_max = rlim.rlim_cur;
	return setrlimit(RLIMIT_NICE, &rlim);
}

__attribute__((warn_unused_result))
static int dropRoot(void) {
	const struct passwd * const p = getpwnam("allears");

	return (p != NULL
	&& setgroups(0, NULL) == 0
	&& setgid(p->pw_gid) == 0
	&& setuid(p->pw_uid) == 0
	&& getgid() == p->pw_gid
	&& getuid() == p->pw_uid
	) ? 0 : -1;
}

static int cgroupMove(void) {
	const int fd = open(AEM_PATH_HOME"/cgroup/_aem/limited/cgroup.procs", O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_WRONLY);
	if (fd < 0 || !validFd(fd)) {syslog(LOG_ERR, "Failed opening limited/cgroup.procs: %m"); return -1;}

	const pid_t pid_num = getpid();
	char pid_txt[32];
	sprintf(pid_txt, "%d", pid_num);
	if (write(fd, pid_txt, strlen(pid_txt)) != (ssize_t)strlen(pid_txt)) {syslog(LOG_ERR, "Failed writing to limited/cgroup.procs: %m"); close(fd); return -1;}

	close(fd);
	return 0;
}

static int process_new(const int type) {
	wipeKeys();
	close(AEM_FD_SERVER); // fd0 freed
	close(AEM_FD_PIPE_WR); // fd2 freed

	if (loadExec(type) != 0) exit(EXIT_FAILURE); // fd0=AEM_FD_BINARY
	sodium_memzero(key_bin, crypto_secretbox_KEYBYTES);
	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, "") != 0) {syslog(LOG_ERR, "[%d] Failed private mount", type); exit(EXIT_FAILURE);} // With CLONE_NEWNS, prevent propagation of mount events to other mount namespaces
	if (setpriority(PRIO_PROCESS, 0, typeNice[type])    != 0) {syslog(LOG_ERR, "[%d] Failed setpriority()", type); exit(EXIT_FAILURE);}
	if (cgroupMove()      != 0) {syslog(LOG_ERR, "[%d] Failed cgroupMove()",  type); exit(EXIT_FAILURE);}
	if (createMount(type) != 0) {syslog(LOG_ERR, "[%d] Failed createMount()", type); exit(EXIT_FAILURE);} // fd2=AEM_FD_ROOT
	if (setLimits(type)   != 0) {syslog(LOG_ERR, "[%d] Failed setLimits()",   type); exit(EXIT_FAILURE);}
	if (dropRoot()        != 0) {syslog(LOG_ERR, "[%d] Failed dropRoot()",    type); exit(EXIT_FAILURE);}
	if (setCaps(type)     != 0) {syslog(LOG_ERR, "[%d] Failed setCaps()",     type); exit(EXIT_FAILURE);}
	umask((type == AEM_PROCESSTYPE_STORAGE) ? 0077 : 0777);

	fexecve(AEM_FD_BINARY, (char*[]){NULL}, (char*[]){NULL});

	// Only runs if exec failed
	close(AEM_FD_BINARY);  // fd0
	close(AEM_FD_PIPE_RD); // fd1
	close(AEM_FD_ROOT);    // fd2
	syslog(LOG_ERR, "[%d] Failed starting process: %m", type);
	exit(EXIT_FAILURE);
}

static int sendIntComKeys(const int type) {
	struct intcom_keyBundle bundle;
	bzero(&bundle, sizeof(bundle));

	switch (type) {
		case AEM_PROCESSTYPE_WEB_CLR:
		case AEM_PROCESSTYPE_WEB_ONI:
			return 0;

		case AEM_PROCESSTYPE_ACCOUNT:
			crypto_kdf_derive_from_key(bundle.server[AEM_INTCOM_CLIENT_API], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_API, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.server[AEM_INTCOM_CLIENT_MTA], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_MTA, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.client[AEM_INTCOM_SERVER_STO], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_ACC, "AEM_IC.1", key_ic);
		break;

		case AEM_PROCESSTYPE_DELIVER:
			crypto_kdf_derive_from_key(bundle.client[AEM_INTCOM_SERVER_ENQ], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_DLV, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.client[AEM_INTCOM_SERVER_STO], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_DLV, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.stream,   crypto_secretstream_xchacha20poly1305_KEYBYTES, AEM_KEYNUM_INTCOM_STREAM,      "AEM_IC.1", key_ic);
		break;

		case AEM_PROCESSTYPE_ENQUIRY:
			crypto_kdf_derive_from_key(bundle.server[AEM_INTCOM_CLIENT_API], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_API, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.server[AEM_INTCOM_CLIENT_DLV], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_DLV, "AEM_IC.1", key_ic);
		break;

		case AEM_PROCESSTYPE_STORAGE:
			crypto_kdf_derive_from_key(bundle.server[AEM_INTCOM_CLIENT_ACC], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_ACC, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.server[AEM_INTCOM_CLIENT_API], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_API, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.server[AEM_INTCOM_CLIENT_DLV], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_DLV, "AEM_IC.1", key_ic);
		break;

		case AEM_PROCESSTYPE_API_CLR:
		case AEM_PROCESSTYPE_API_ONI:
			crypto_kdf_derive_from_key(bundle.client[AEM_INTCOM_SERVER_ACC], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_API, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.client[AEM_INTCOM_SERVER_ENQ], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_API, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.client[AEM_INTCOM_SERVER_STO], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_API, "AEM_IC.1", key_ic);
		break;

		case AEM_PROCESSTYPE_MTA:
			crypto_kdf_derive_from_key(bundle.client[AEM_INTCOM_SERVER_ACC], crypto_secretbox_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_MTA, "AEM_IC.1", key_ic);
			crypto_kdf_derive_from_key(bundle.stream,   crypto_secretstream_xchacha20poly1305_KEYBYTES, AEM_KEYNUM_INTCOM_STREAM,      "AEM_IC.1", key_ic);
		break;

		default: return -1;
	}

	const ssize_t bytes = write(AEM_FD_PIPE_WR, &bundle, sizeof(bundle));
	sodium_memzero(&bundle, sizeof(bundle));
	return (bytes == sizeof(bundle))? 0 : -1;
}

static int process_spawn(const int type, const unsigned char * const key_forward) {
	int freeSlot = -1;
	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_WEB_CLR || type == AEM_PROCESSTYPE_WEB_ONI || type == AEM_PROCESSTYPE_API_CLR || type == AEM_PROCESSTYPE_API_ONI) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemPid[type][i] == 0) {
				freeSlot = i;
				break;
			}
		}

		if (freeSlot < 0) return 60;
	}

	int fd[2];
	if (
	   pipe2(fd, O_DIRECT) != 0
	|| fd[0] != AEM_FD_PIPE_RD
	|| fd[1] != AEM_FD_PIPE_WR
	) return 61;

	struct clone_args cloneArgs;
	bzero(&cloneArgs, sizeof(struct clone_args));
	cloneArgs.flags = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS | CLONE_UNTRACED | CLONE_CLEAR_SIGHAND;
	if (type == AEM_PROCESSTYPE_WEB_CLR || type == AEM_PROCESSTYPE_WEB_ONI) cloneArgs.flags |= CLONE_NEWPID; // Doesn't interact with other processes

	const long pid = syscall(SYS_clone3, &cloneArgs, sizeof(struct clone_args));
	if (pid < 0) return 62;
	if (pid == 0) exit(process_new(type));

	close(AEM_FD_PIPE_RD); // fd1 freed

	bool fail = false;

	// Pids
	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT:
			fail = (write(AEM_FD_PIPE_WR, &pid_storage, sizeof(pid_t)) != sizeof(pid_t));
		break;

		case AEM_PROCESSTYPE_DELIVER:
			fail = (write(AEM_FD_PIPE_WR, (pid_t[]){pid_enquiry, pid_storage}, sizeof(pid_t) * 2) != sizeof(pid_t) * 2);
		break;

		case AEM_PROCESSTYPE_MTA:
			fail = (write(AEM_FD_PIPE_WR, (pid_t[]){pid_account, pid_deliver}, sizeof(pid_t) * 2) != sizeof(pid_t) * 2);
		break;

		case AEM_PROCESSTYPE_API_CLR:
		case AEM_PROCESSTYPE_API_ONI:
			fail = (write(AEM_FD_PIPE_WR, (pid_t[]){pid_account, pid_storage, pid_enquiry}, sizeof(pid_t) * 3) != sizeof(pid_t) * 3);
		break;

		/* Nothing:
		case AEM_PROCESSTYPE_ENQUIRY:
		case AEM_PROCESSTYPE_STORAGE:
		case AEM_PROCESSTYPE_WEB_CLR:
		case AEM_PROCESSTYPE_WEB_ONI:
		*/
	}

	if (!fail && key_forward != NULL) {
		fail = (write(AEM_FD_PIPE_WR, key_forward, crypto_kdf_KEYBYTES) != crypto_kdf_KEYBYTES);
	}

	if (!fail) {
		fail = (sendIntComKeys(type) != 0);
	}

	close(AEM_FD_PIPE_WR);

	if (fail) {
		kill(pid, SIGKILL);
		return 63;
	}

	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT: pid_account = pid; break;
		case AEM_PROCESSTYPE_DELIVER: pid_deliver = pid; break;
		case AEM_PROCESSTYPE_ENQUIRY: pid_enquiry = pid; break;
		case AEM_PROCESSTYPE_STORAGE: pid_storage = pid; break;

		default: aemPid[type][freeSlot] = pid;
	}

	return 0;
}

static void process_kill(const int type, const pid_t pid, const int sig) {
	syslog(LOG_INFO, "Termination of process %d requested", pid);
	if (type < 0 || type > 2 || pid < 1) return;

	bool found = false;
	for (int i = 0; i < AEM_MAXPROCESSES; i++) {
		if (aemPid[type][i] == pid) {
			found = true;
			break;
		}
	}

	if (!found) {syslog(LOG_INFO, "Process %d was not found", pid); return;}
	if (!process_exists(pid)) {syslog(LOG_INFO, "Process %d not valid", pid); return;}

	kill(pid, sig);
}

static void cryptSend(void) {
	unsigned char decrypted[AEM_MANAGER_RESLEN_DECRYPTED];
	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < AEM_MAXPROCESSES; j++) {
			const int start = ((i * AEM_MAXPROCESSES) + j) * 4;
			memcpy(decrypted + start, &(aemPid[i][j]), 4);
		}
	}

	unsigned char encrypted[AEM_MANAGER_RESLEN_ENCRYPTED];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	if (crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, decrypted, AEM_MANAGER_RESLEN_DECRYPTED, encrypted, key_mng) == 0) {
		if (send(AEM_FD_CLIENT, encrypted, AEM_MANAGER_RESLEN_ENCRYPTED, 0) != AEM_MANAGER_RESLEN_ENCRYPTED) {
			syslog(LOG_WARNING, "Failed send");
		}
	} else {
		syslog(LOG_WARNING, "Failed encrypt");
	}
}

static void respond_manager(void) {
	unsigned char encrypted[AEM_MANAGER_CMDLEN_ENCRYPTED];
	if (recv(AEM_FD_CLIENT, encrypted, AEM_MANAGER_CMDLEN_ENCRYPTED, 0) != AEM_MANAGER_CMDLEN_ENCRYPTED) {
		syslog(LOG_WARNING, "Failed recv");
		close(AEM_FD_CLIENT);
		return;
	}

	close(AEM_FD_CLIENT);

	unsigned char decrypted[AEM_MANAGER_CMDLEN_DECRYPTED];
	if (crypto_secretbox_open_easy(decrypted, encrypted + crypto_secretbox_NONCEBYTES, AEM_MANAGER_CMDLEN_ENCRYPTED - crypto_secretbox_NONCEBYTES, encrypted, key_mng) != 0) {
		syslog(LOG_WARNING, "Failed decrypt");
		return;
	}

	uint32_t num;
	memcpy(&num, decrypted + 2, 4);

	switch (decrypted[0]) {
		case '\0': break; // No action, only requesting info

		case 'T': { // Request termination
			process_kill(decrypted[1], num, SIGUSR1);
			break;
		}

		case 'K': { // Request immediate termination (kill)
			process_kill(decrypted[1], num, SIGUSR2);
			break;
		}

		case 'S': { // Spawn
			if (num > AEM_MAXPROCESSES) return;

			for (unsigned int i = 0; i < num; i++) {
				if (process_spawn(decrypted[1], (decrypted[1] == AEM_PROCESSTYPE_API_CLR || decrypted[1] == AEM_PROCESSTYPE_API_ONI) ? key_api : NULL) != 0) return;
			}

			break;
		}

		default: {syslog(LOG_WARNING, "Invalid command"); return;}
	}

	refreshPids();
//	cryptSend();
}

static bool verifyStatus(void) {
	return (
		   pid_account > 0
		&& pid_deliver > 0
		&& pid_enquiry > 0
		&& pid_storage > 0
	);
}

static int takeConnections(void) {
	while (!terminate) {
		if (accept4(AEM_FD_SERVER, NULL, NULL, SOCK_CLOEXEC) != AEM_FD_CLIENT) continue;
		respond_manager();
	}

	close(AEM_FD_SERVER);
	wipeKeys();
	sodium_memzero(key_bin, crypto_secretbox_KEYBYTES);
	return 0;
}

int setupManager(void) {
	unsigned char master[crypto_kdf_KEYBYTES];
	if (getKey(master) != 0) {sodium_memzero(master, crypto_kdf_KEYBYTES); return 51;}
	if (close_range(0, UINT_MAX, 0) != 0) {sodium_memzero(master, crypto_kdf_KEYBYTES); return 52;}
	if (createSocket(AEM_PORT_MANAGER, false, AEM_TIMEOUT_MANAGER_RCV, AEM_TIMEOUT_MANAGER_SND) != AEM_FD_SERVER) {sodium_memzero(master, crypto_kdf_KEYBYTES); return 53;}

	bzero(aemPid, sizeof(aemPid));
	crypto_kdf_derive_from_key(key_bin, crypto_secretbox_KEYBYTES, 1, "AEM_Bin0", master);
	randombytes_buf(key_ic, crypto_kdf_KEYBYTES);

	unsigned char key_tmp[crypto_kdf_KEYBYTES];
	int ret = (process_spawn(AEM_PROCESSTYPE_ENQUIRY, NULL));
	if (ret == 0) {
		crypto_kdf_derive_from_key(key_tmp, crypto_kdf_KEYBYTES, 1, "AEM_Sto0", master);
		ret = process_spawn(AEM_PROCESSTYPE_STORAGE, key_tmp);
	}
	if (ret == 0) {
		crypto_kdf_derive_from_key(key_tmp, crypto_kdf_KEYBYTES, 1, "AEM_Dlv0", master);
		ret = process_spawn(AEM_PROCESSTYPE_DELIVER, key_tmp);
	}
	if (ret == 0) {
		crypto_kdf_derive_from_key(key_tmp, crypto_kdf_KEYBYTES, 1, "AEM_Acc0", master);
		ret = process_spawn(AEM_PROCESSTYPE_ACCOUNT, key_tmp);
	}

	sodium_memzero(key_tmp, crypto_kdf_KEYBYTES);

	if (ret != 0) {
		sodium_memzero(key_bin, crypto_kdf_KEYBYTES);
		sodium_memzero(master, crypto_kdf_KEYBYTES);
		return ret;
	}

	crypto_kdf_derive_from_key(key_mng, crypto_secretbox_KEYBYTES, 1, "AEM_Mng0", master);
	crypto_kdf_derive_from_key(key_api, crypto_kdf_KEYBYTES,       1, "AEM_Api0", master);

	sodium_memzero(master, crypto_kdf_KEYBYTES);
	return takeConnections();
}
