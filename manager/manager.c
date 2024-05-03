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

#include "../Global.h"
#include "../Common/CreateSocket.h"
#include "../Common/GetKey.h"
#include "../Common/ValidFd.h"
#include "../IntCom/KeyBundle.h"

#include "mount.h"

#include "manager.h"

#define AEM_FD_SERVER 0
#define AEM_FD_CLIENT 1

enum intcom_keynum {
	AEM_KEYNUM_INTCOM_NULL,
	AEM_KEYNUM_INTCOM_ACCOUNT_API,
	AEM_KEYNUM_INTCOM_ACCOUNT_MTA,
	AEM_KEYNUM_INTCOM_ACCOUNT_STO,
	AEM_KEYNUM_INTCOM_ENQUIRY_API,
	AEM_KEYNUM_INTCOM_ENQUIRY_DLV,
	AEM_KEYNUM_INTCOM_STORAGE_ACC,
	AEM_KEYNUM_INTCOM_STORAGE_API,
	AEM_KEYNUM_INTCOM_STORAGE_DLV,
	AEM_KEYNUM_INTCOM_STREAM
};

static unsigned char key_bin[crypto_aead_aegis256_KEYBYTES];
static unsigned char key_mng[crypto_aead_aegis256_KEYBYTES];
static unsigned char key_ic[AEM_KDF_KEYSIZE];

static const int typeNice[AEM_PROCESSTYPES_COUNT] = AEM_NICE;

static pid_t pid_account = 0;
static pid_t pid_deliver = 0;
static pid_t pid_enquiry = 0;
static pid_t pid_storage = 0;
static pid_t aemPid[5][AEM_MAXPROCESSES];

static volatile sig_atomic_t terminate = 0;

static void wipeKeys(void) {
	sodium_memzero(key_mng, crypto_aead_aegis256_KEYBYTES);
	sodium_memzero(key_ic,  AEM_KDF_KEYSIZE);
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

static void killAll(const int sig) {
	if (pid_account > 0) kill(pid_account, sig);
	if (pid_deliver > 0) kill(pid_deliver, sig);
	if (pid_enquiry > 0) kill(pid_enquiry, sig);
	if (pid_storage > 0) kill(pid_storage, sig);


	for (int type = 0; type < 5; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemPid[type][i] > 0) kill(aemPid[type][i], sig);
		}
	}
}

void sigTerm(const int s) {
	terminate = 1;
}

static int loadExec(const int type) {
	if (memfd_create("aem", MFD_CLOEXEC | MFD_ALLOW_SEALING) != AEM_FD_BINARY) {
		syslog(LOG_ERR, "Failed memfd_create: %m");
		return -1;
	}

	const char * const path[] = AEM_PATH_EXE;
	const int fd = open(path[type], O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0 || !validFd(fd)) {syslog(LOG_ERR, "Failed opening file: %s", path[type]); close(AEM_FD_BINARY); return -1;}

	const off_t bytes = lseek(fd, 0, SEEK_END);
	if (bytes < 1 || bytes > AEM_MAXSIZE_EXEC) {
		syslog(LOG_ERR, "Invalid length on %s", path[type]);
		close(AEM_FD_BINARY);
		close(fd);
		return -1;
	}

	unsigned char enc[bytes];
	if (pread(fd, enc, bytes, 0) != bytes) {
		syslog(LOG_ERR, "Failed reading %s: %m", path[type]);
		close(AEM_FD_BINARY);
		close(fd);
		return -1;
	}
	close(fd);

	const size_t lenDec = bytes - crypto_aead_aegis256_NPUBBYTES - crypto_aead_aegis256_ABYTES;
	unsigned char dec[lenDec];
	if (crypto_aead_aegis256_decrypt(dec, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, bytes - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, key_bin) == -1) {
		syslog(LOG_ERR, "Failed decrypting %s (size %d)", path[type], bytes);
		close(AEM_FD_BINARY);
		return -1;
	}

	if (
	   write(AEM_FD_BINARY, dec, lenDec) != (ssize_t)lenDec
	|| fcntl(AEM_FD_BINARY, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0
	) {
		syslog(LOG_ERR, "Failed loadExec: %m");
		close(AEM_FD_BINARY);
		return -1;
	}

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

		case AEM_PROCESSTYPE_API:
		case AEM_PROCESSTYPE_MTA:
			cap[2] = CAP_IPC_LOCK;
			cap[3] = CAP_NET_BIND_SERVICE;
			cap[4] = CAP_NET_RAW;
			numCaps = 5;
		break;

		case AEM_PROCESSTYPE_WEB:
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
		case AEM_PROCESSTYPE_WEB:
		case AEM_PROCESSTYPE_API: rlim.rlim_cur = 4; break;
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
	sodium_memzero(key_bin, crypto_aead_aegis256_KEYBYTES);
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
	bzero(&bundle, sizeof(struct intcom_keyBundle));

	switch (type) {
		case AEM_PROCESSTYPE_WEB:
			return 0;

		case AEM_PROCESSTYPE_ACCOUNT:
			aem_kdf(bundle.server[AEM_INTCOM_CLIENT_API], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_API, key_ic);
			aem_kdf(bundle.server[AEM_INTCOM_CLIENT_MTA], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_MTA, key_ic);
			aem_kdf(bundle.server[AEM_INTCOM_CLIENT_STO], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_STO, key_ic);
			aem_kdf(bundle.client[AEM_INTCOM_SERVER_STO], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_ACC, key_ic);
		break;

		case AEM_PROCESSTYPE_DELIVER:
			aem_kdf(bundle.client[AEM_INTCOM_SERVER_ENQ], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_DLV, key_ic);
			aem_kdf(bundle.client[AEM_INTCOM_SERVER_STO], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_DLV, key_ic);
			aem_kdf(bundle.stream,       crypto_secretstream_xchacha20poly1305_KEYBYTES, AEM_KEYNUM_INTCOM_STREAM,      key_ic);
		break;

		case AEM_PROCESSTYPE_ENQUIRY:
			aem_kdf(bundle.server[AEM_INTCOM_CLIENT_API], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_API, key_ic);
			aem_kdf(bundle.server[AEM_INTCOM_CLIENT_DLV], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_DLV, key_ic);
		break;

		case AEM_PROCESSTYPE_STORAGE:
			aem_kdf(bundle.server[AEM_INTCOM_CLIENT_ACC], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_ACC, key_ic);
			aem_kdf(bundle.server[AEM_INTCOM_CLIENT_API], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_API, key_ic);
			aem_kdf(bundle.server[AEM_INTCOM_CLIENT_DLV], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_DLV, key_ic);
			aem_kdf(bundle.client[AEM_INTCOM_SERVER_ACC], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_STO, key_ic);
		break;

		case AEM_PROCESSTYPE_API:
			aem_kdf(bundle.client[AEM_INTCOM_SERVER_ACC], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_API, key_ic);
			aem_kdf(bundle.client[AEM_INTCOM_SERVER_ENQ], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_API, key_ic);
			aem_kdf(bundle.client[AEM_INTCOM_SERVER_STO], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_API, key_ic);
		break;

		case AEM_PROCESSTYPE_MTA:
			aem_kdf(bundle.client[AEM_INTCOM_SERVER_ACC], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_MTA, key_ic);
			aem_kdf(bundle.stream,       crypto_secretstream_xchacha20poly1305_KEYBYTES, AEM_KEYNUM_INTCOM_STREAM,      key_ic);
		break;

		default: return -1;
	}

	const ssize_t bytes = write(AEM_FD_PIPE_WR, &bundle, sizeof(bundle));
	sodium_memzero(&bundle, sizeof(bundle));
	return (bytes == sizeof(bundle))? 0 : -1;
}

static int process_spawn(const int type, const unsigned char * const key_forward) {
	int freeSlot = -1;
	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_WEB) {
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
	if (type == AEM_PROCESSTYPE_WEB) cloneArgs.flags |= CLONE_NEWPID; // Doesn't interact with other processes

	const long pid = syscall(SYS_clone3, &cloneArgs, sizeof(struct clone_args));
	if (pid < 0) {close(fd[0]); close(fd[1]); return 62;}
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

		case AEM_PROCESSTYPE_API:
			fail = (write(AEM_FD_PIPE_WR, (pid_t[]){pid_account, pid_storage, pid_enquiry}, sizeof(pid_t) * 3) != sizeof(pid_t) * 3);
		break;

		/* Nothing:
		case AEM_PROCESSTYPE_ENQUIRY:
		case AEM_PROCESSTYPE_STORAGE:
		case AEM_PROCESSTYPE_WEB:
		*/
	}

	if (!fail && key_forward != NULL) {
		fail = (write(AEM_FD_PIPE_WR, key_forward, AEM_KDF_KEYSIZE) != AEM_KDF_KEYSIZE);
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
	unsigned char dec[AEM_MANAGER_RESLEN_DEC];
	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < AEM_MAXPROCESSES; j++) {
			const int start = ((i * AEM_MAXPROCESSES) + j) * 4;
			memcpy(dec + start, &(aemPid[i][j]), 4);
		}
	}

	unsigned char enc[AEM_MANAGER_RESLEN_ENC];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	if (crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, dec, AEM_MANAGER_RESLEN_DEC, NULL, 0, NULL, enc, key_mng) == 0) {
		if (send(AEM_FD_CLIENT, enc, AEM_MANAGER_RESLEN_ENC, 0) != AEM_MANAGER_RESLEN_ENC) {
			syslog(LOG_WARNING, "Failed send");
		}
	} else {
		syslog(LOG_WARNING, "Failed encrypt");
	}
}

static void respond_manager(void) {
	unsigned char enc[AEM_MANAGER_CMDLEN_ENC];
	if (recv(AEM_FD_CLIENT, enc, AEM_MANAGER_CMDLEN_ENC, 0) != AEM_MANAGER_CMDLEN_ENC) {
		syslog(LOG_WARNING, "Manager Protocol - failed recv: %m");
		close(AEM_FD_CLIENT);
		return;
	}

	close(AEM_FD_CLIENT);

	unsigned char dec[AEM_MANAGER_CMDLEN_DEC];
	if (crypto_aead_aegis256_decrypt(dec, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, AEM_MANAGER_CMDLEN_ENC - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, key_mng) != 0) {
		syslog(LOG_WARNING, "Manager Protocol: Failed decrypt");
		return;
	}

	uint32_t num;
	memcpy(&num, dec + 2, 4);

	switch (dec[0]) {
		case '\0': break; // No action, only requesting info

		case 'T': { // Request termination
			process_kill(dec[1], num, SIGUSR1);
			break;
		}

		case 'K': { // Request immediate termination (kill)
			process_kill(dec[1], num, SIGUSR2);
			break;
		}

		case 'S': { // Spawn
			if (num > AEM_MAXPROCESSES) return;

			for (unsigned int i = 0; i < num; i++) {
				if (process_spawn(dec[1], NULL) != 0) return;
			}

			break;
		}

		default: {syslog(LOG_WARNING, "Manager Protocol: Invalid command"); return;}
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
	while (terminate == 0) {
		if (accept4(AEM_FD_SERVER, NULL, NULL, SOCK_CLOEXEC) != AEM_FD_CLIENT) continue;
		respond_manager();
	}

	wipeKeys();
	sodium_memzero(key_bin, crypto_aead_aegis256_KEYBYTES);
	umount2(AEM_PATH_MOUNTDIR, MNT_DETACH);
	syslog(LOG_INFO, "Terminating");
	return 0;
}

int setupManager(void) {
	unsigned char smk[AEM_KDF_KEYSIZE];
	if (getKey(smk) != 0) {sodium_memzero(smk, AEM_KDF_KEYSIZE); return 51;}
	if (close_range(0, UINT_MAX, 0) != 0) {sodium_memzero(smk, AEM_KDF_KEYSIZE); return 52;}
	if (createSocket(false, AEM_TIMEOUT_MANAGER_RCV, AEM_TIMEOUT_MANAGER_SND) != AEM_FD_SERVER) {sodium_memzero(smk, AEM_KDF_KEYSIZE); return 53;}

	bzero(aemPid, sizeof(aemPid));
	aem_kdf(key_bin, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_SMK_BIN, smk);
	randombytes_buf(key_ic, AEM_KDF_KEYSIZE);

	unsigned char key_tmp[AEM_KDF_KEYSIZE];
	int ret = process_spawn(AEM_PROCESSTYPE_ENQUIRY, NULL);

	if (ret == 0) {
		aem_kdf(key_tmp, AEM_KDF_KEYSIZE, AEM_KDF_KEYID_SMK_STO, smk);
		ret = process_spawn(AEM_PROCESSTYPE_STORAGE, key_tmp);
	}

	if (ret == 0) {
		ret = process_spawn(AEM_PROCESSTYPE_DELIVER, NULL);
	}

	if (ret == 0) {
		aem_kdf(key_tmp, AEM_KDF_KEYSIZE, AEM_KDF_KEYID_SMK_ACC, smk);
		ret = process_spawn(AEM_PROCESSTYPE_ACCOUNT, key_tmp);
	}

	sodium_memzero(key_tmp, AEM_KDF_KEYSIZE);

	if (ret != 0) {
		sodium_memzero(key_bin, crypto_aead_aegis256_KEYBYTES);
		sodium_memzero(smk, AEM_KDF_KEYSIZE);
		return ret;
	}

	aem_kdf(key_mng, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_SMK_MNG, smk);

	sodium_memzero(smk, AEM_KDF_KEYSIZE);
	return takeConnections();
}
