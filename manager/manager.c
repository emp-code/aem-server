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
#include <sys/capability.h>
#include <sys/mman.h> // for memfd_create()
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/CreateSocket.h"
#include "../Common/GetKey.h"
#include "../Common/ValidFd.h"
#include "../Global.h"

#include "mount.h"

#include "manager.h"

#define AEM_LEN_FILE_MAX 128

// AEM_FD_PIPE_RD in Global.h
#define AEM_FD_PIPE_WR (AEM_FD_PIPE_RD + 1)

static unsigned char master[AEM_LEN_KEY_MASTER];
static unsigned char key_mng[AEM_LEN_KEY_MNG];
static unsigned char key_acc[AEM_LEN_KEY_ACC];
static unsigned char key_api[AEM_LEN_KEY_API];
static unsigned char key_mng[AEM_LEN_KEY_MNG];
static unsigned char key_sig[AEM_LEN_KEY_SIG];
static unsigned char key_sto[AEM_LEN_KEY_STO];
static unsigned char slt_shd[AEM_LEN_SLT_SHD];

static const int typeNice[AEM_PROCESSTYPES_COUNT] = AEM_NICE;

static pid_t pid_account = 0;
static pid_t pid_deliver = 0;
static pid_t pid_enquiry = 0;
static pid_t pid_storage = 0;
static pid_t aemPid[5][AEM_MAXPROCESSES];

static int sockMain = -1;
static bool terminate = false;

int getMasterKey(void) {
	return getKey(master);
}

static void wipeKeys(void) {
	sodium_memzero(master, AEM_LEN_KEY_MASTER);
	sodium_memzero(key_mng, AEM_LEN_KEY_MNG);
	sodium_memzero(key_acc, AEM_LEN_KEY_ACC);
	sodium_memzero(key_api, AEM_LEN_KEY_API);
	sodium_memzero(key_mng, AEM_LEN_KEY_MNG);
	sodium_memzero(key_sig, AEM_LEN_KEY_SIG);
	sodium_memzero(key_sto, AEM_LEN_KEY_STO);
	sodium_memzero(slt_shd, AEM_LEN_SLT_SHD);
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

static int loadFile(const char * const path, unsigned char * const target, size_t * const len, const off_t expectedLen, const off_t maxLen) {
	const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0 || !validFd(fd)) {syslog(LOG_ERR, "Failed opening file: %s", path); return -1;}

	off_t bytes = lseek(fd, 0, SEEK_END);
	if (bytes < 1 || lseek(fd, 0, SEEK_SET) != 0 || bytes > maxLen - crypto_secretbox_NONCEBYTES || (expectedLen != 0 && bytes != expectedLen + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)) {
		syslog(LOG_ERR, "Failed lseek or invalid length on %s", path);
		close(fd);
		return -1;
	}

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	off_t readBytes = read(fd, nonce, crypto_secretbox_NONCEBYTES);
	if (readBytes != crypto_secretbox_NONCEBYTES) {syslog(LOG_ERR, "Failed reading %s", path); close(fd); return -1;}
	bytes -= crypto_secretbox_NONCEBYTES;

	unsigned char enc[bytes];
	readBytes = read(fd, enc, bytes);
	close(fd);
	if (readBytes != bytes) {syslog(LOG_ERR, "Failed reading %s", path); return -1;}

	if (len != NULL) *len = bytes - crypto_secretbox_MACBYTES;

	if (crypto_secretbox_open_easy(target, enc, bytes, nonce, master) != 0) {
		syslog(LOG_ERR, "Failed decrypting %s", path);
		return -1;
	}

	return 0;
}

static int loadExec(void) {
	unsigned char * const tmp = sodium_malloc(AEM_MAXSIZE_EXEC);
	if (tmp == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}

	size_t lenTmp;
	const char * const path[] = AEM_PATH_EXE;

	for (int i = 0; i < AEM_PROCESSTYPES_COUNT; i++) {
		const int binfd = memfd_create("aem", MFD_CLOEXEC | MFD_ALLOW_SEALING);
		if (binfd != AEM_BINFD_OFFSET + i) {
			if (binfd < 0) {
				syslog(LOG_ERR, "Failed memfd_create: %m");
			} else {
				syslog(LOG_ERR, "Invalid fd: expected %d, got %d", AEM_BINFD_OFFSET + i, binfd);
			}

			sodium_free(tmp);
			return -1;
		}

		if (
		   loadFile(path[i], tmp, &lenTmp, 0, AEM_MAXSIZE_EXEC) != 0
		|| write(binfd, tmp, lenTmp) != (ssize_t)lenTmp
		|| fcntl(binfd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0
		) {
			syslog(LOG_ERR, "Failed loadExec: %m");
			sodium_free(tmp);
			return -1;
		}
	}

	sodium_free(tmp);
	return 0;
}

int loadFiles(void) {
	return (
	   loadFile(AEM_PATH_KEY_ACC, key_acc, NULL, AEM_LEN_KEY_ACC, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_KEY_API, key_api, NULL, AEM_LEN_KEY_API, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_KEY_MNG, key_mng, NULL, AEM_LEN_KEY_MNG, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_KEY_SIG, key_sig, NULL, AEM_LEN_KEY_SIG, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_KEY_STO, key_sto, NULL, AEM_LEN_KEY_STO, AEM_LEN_FILE_MAX) == 0
	&& loadFile(AEM_PATH_SLT_SHD, slt_shd, NULL, AEM_LEN_SLT_SHD, AEM_LEN_FILE_MAX) == 0
	) ? loadExec() : -1;
}

static int setCaps(const int type) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	// Ambient capabilities
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) return -1;

	cap_value_t cap[4];
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

		case AEM_PROCESSTYPE_WEB_CLR:
		case AEM_PROCESSTYPE_WEB_ONI:
		case AEM_PROCESSTYPE_API_CLR:
		case AEM_PROCESSTYPE_API_ONI:
		case AEM_PROCESSTYPE_MTA:
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

static int setSubLimits(const int type) {
	struct rlimit rlim;

	if (type != AEM_PROCESSTYPE_ACCOUNT && type != AEM_PROCESSTYPE_STORAGE) {
		rlim.rlim_cur = 0;
		rlim.rlim_max = 0;
		if (setrlimit(RLIMIT_FSIZE, &rlim) != 0) return -1;
	}

	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT: rlim.rlim_cur = 4; break;
		case AEM_PROCESSTYPE_DELIVER: rlim.rlim_cur = 4; break;
		case AEM_PROCESSTYPE_ENQUIRY: rlim.rlim_cur = 15; break;
		case AEM_PROCESSTYPE_STORAGE: rlim.rlim_cur = 5; break;

		case AEM_PROCESSTYPE_MTA:     rlim.rlim_cur = 4; break;
		case AEM_PROCESSTYPE_WEB_CLR:
		case AEM_PROCESSTYPE_WEB_ONI: rlim.rlim_cur = 3; break;
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
	close(sockMain); // fd0 freed

	if (type != AEM_PROCESSTYPE_ENQUIRY && type != AEM_PROCESSTYPE_WEB_CLR && type != AEM_PROCESSTYPE_WEB_ONI) {
		// This process type uses a pipe, but doesn't need its writing side
		close(AEM_FD_PIPE_WR);
	}

	for (int i = 0; i < AEM_PROCESSTYPES_COUNT; i++) {
		if (i != type) close(AEM_BINFD_OFFSET + i);
	}

	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, "") != 0) {syslog(LOG_ERR, "[%d] Failed private mount", type); exit(EXIT_FAILURE);} // With CLONE_NEWNS, prevent propagation of mount events to other mount namespaces
	if (setpriority(PRIO_PROCESS, 0, typeNice[type])    != 0) {syslog(LOG_ERR, "[%d] Failed setpriority()", type); exit(EXIT_FAILURE);}
	if (prctl(PR_SET_PDEATHSIG, SIGUSR2, 0, 0, 0)       != 0) {syslog(LOG_ERR, "[%d] Failed prctl()",       type); exit(EXIT_FAILURE);}

	if (cgroupMove()       != 0) {syslog(LOG_ERR, "[%d] Failed cgroupMove()",   type); exit(EXIT_FAILURE);}
	if (createMount(type)  != 0) {syslog(LOG_ERR, "[%d] Failed createMount()",  type); exit(EXIT_FAILURE);} // fd0 becomes pivot-dir fd
	if (setSubLimits(type) != 0) {syslog(LOG_ERR, "[%d] Failed setSubLimits()", type); exit(EXIT_FAILURE);}
	if (dropRoot()         != 0) {syslog(LOG_ERR, "[%d] Failed dropRoot()",     type); exit(EXIT_FAILURE);}
	if (setCaps(type)      != 0) {syslog(LOG_ERR, "[%d] Failed setCaps()",      type); exit(EXIT_FAILURE);}

	fexecve(AEM_BINFD_OFFSET + type, (char*[]){NULL}, (char*[]){NULL});

	// Only runs if exec failed
	close(0); // pivot-dir fd
	close(AEM_BINFD_OFFSET + type);
	syslog(LOG_ERR, "[%d] Failed starting process: %m", type);
	exit(EXIT_FAILURE);
}

static int process_spawn(const int type) {
	int freeSlot = -1;
	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_WEB_CLR || type == AEM_PROCESSTYPE_WEB_ONI || type == AEM_PROCESSTYPE_API_CLR || type == AEM_PROCESSTYPE_API_ONI) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemPid[type][i] == 0) {
				freeSlot = i;
				break;
			}
		}

		if (freeSlot < 0) return -1;
	}

	if (type != AEM_PROCESSTYPE_ENQUIRY && type != AEM_PROCESSTYPE_WEB_CLR && type != AEM_PROCESSTYPE_WEB_ONI) {
		int fd[2];
		if (pipe2(fd, O_DIRECT) < 0 || fd[0] < 0 || fd[1] < 0) {syslog(LOG_ERR, "Failed creating pipes: %m"); return -1;}
		if (fd[0] != AEM_FD_PIPE_RD || fd[1] != AEM_FD_PIPE_WR) {syslog(LOG_ERR, "Failed creating pipes: %d/%d", fd[0], fd[1]); return -1;}
	}

	struct clone_args cloneArgs;
	bzero(&cloneArgs, sizeof(struct clone_args));
	cloneArgs.flags = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS | CLONE_UNTRACED | CLONE_CLEAR_SIGHAND;
	if (type == AEM_PROCESSTYPE_WEB_CLR || type == AEM_PROCESSTYPE_WEB_ONI) cloneArgs.flags |= CLONE_NEWPID; // Doesn't interact with other processes

	const long pid = syscall(SYS_clone3, &cloneArgs, sizeof(struct clone_args));
	if (pid < 0) {syslog(LOG_ERR, "Failed clone3: %m"); return -1;}
	if (pid == 0) exit(process_new(type));

	if (type != AEM_PROCESSTYPE_ENQUIRY && type != AEM_PROCESSTYPE_WEB_CLR && type != AEM_PROCESSTYPE_WEB_ONI) {
		// This process type uses a pipe, but Manager doesn't need its reading side
		close(AEM_FD_PIPE_RD);
	}

	bool fail = false;
	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT:
			fail = (
			   write(AEM_FD_PIPE_WR, &pid_storage, sizeof(pid_t)) != sizeof(pid_t)
			|| write(AEM_FD_PIPE_WR, key_acc, AEM_LEN_KEY_ACC) != AEM_LEN_KEY_ACC
			|| write(AEM_FD_PIPE_WR, slt_shd, AEM_LEN_SLT_SHD) != AEM_LEN_SLT_SHD
			);
		break;

		case AEM_PROCESSTYPE_DELIVER:
			fail = (
			   write(AEM_FD_PIPE_WR, (pid_t[]){pid_enquiry, pid_storage}, sizeof(pid_t) * 2) != sizeof(pid_t) * 2
			|| write(AEM_FD_PIPE_WR, key_sig, AEM_LEN_KEY_SIG) != AEM_LEN_KEY_SIG
			);
		break;

		case AEM_PROCESSTYPE_STORAGE:
			fail = (write(AEM_FD_PIPE_WR, key_sto, AEM_LEN_KEY_STO) != AEM_LEN_KEY_STO);
		break;

		case AEM_PROCESSTYPE_MTA:
			fail = (write(AEM_FD_PIPE_WR, (pid_t[]){pid_account, pid_deliver}, sizeof(pid_t) * 2) != sizeof(pid_t) * 2);
		break;

		case AEM_PROCESSTYPE_API_CLR:
		case AEM_PROCESSTYPE_API_ONI:
			fail = (
			   write(AEM_FD_PIPE_WR, (pid_t[]){pid_account, pid_storage, pid_enquiry}, sizeof(pid_t) * 3) != sizeof(pid_t) * 3
			|| write(AEM_FD_PIPE_WR, key_api, AEM_LEN_KEY_API) != AEM_LEN_KEY_API
			|| write(AEM_FD_PIPE_WR, key_sig, AEM_LEN_KEY_SIG) != AEM_LEN_KEY_SIG
			);
		break;

		/* Nothing:
		case AEM_PROCESSTYPE_ENQUIRY:
		case AEM_PROCESSTYPE_WEB_CLR:
		case AEM_PROCESSTYPE_WEB_ONI:
		*/
	}

	if (fail) kill(pid, SIGKILL);

	close(AEM_FD_PIPE_WR);

	if (fail) {
		syslog(LOG_ERR, "Failed writing to pipe: %m");
		return -1;
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

static void cryptSend(const int sock) {
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
		if (send(sock, encrypted, AEM_MANAGER_RESLEN_ENCRYPTED, 0) != AEM_MANAGER_RESLEN_ENCRYPTED) {
			syslog(LOG_WARNING, "Failed send");
		}
	} else {
		syslog(LOG_WARNING, "Failed encrypt");
	}
}

static void respond_manager(const int sock) {
	unsigned char encrypted[AEM_MANAGER_CMDLEN_ENCRYPTED];
	if (recv(sock, encrypted, AEM_MANAGER_CMDLEN_ENCRYPTED, 0) != AEM_MANAGER_CMDLEN_ENCRYPTED) {
		syslog(LOG_WARNING, "Failed recv");
		close(sock);
		return;
	}

	close(sock);

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
				if (process_spawn(decrypted[1]) != 0) return;
			}

			break;
		}

		default: {syslog(LOG_WARNING, "Invalid command"); return;}
	}

	refreshPids();
//	cryptSend(sock);
}

static bool verifyStatus(void) {
	return (
		   pid_account > 0
		&& pid_deliver > 0
		&& pid_enquiry > 0
		&& pid_storage > 0
	);
}

int receiveConnections(void) {
	sockMain = createSocket(AEM_PORT_MANAGER, false, AEM_TIMEOUT_MANAGER_RCV, AEM_TIMEOUT_MANAGER_SND);
	if (sockMain != 0) {syslog(LOG_ERR, "sm=%d", sockMain); return -1;}
	if (loadFiles() != 0) {syslog(LOG_ERR, "Failed loading files"); return -1;}

	if (
	   process_spawn(AEM_PROCESSTYPE_ENQUIRY) != 0
	|| process_spawn(AEM_PROCESSTYPE_STORAGE) != 0
	|| process_spawn(AEM_PROCESSTYPE_DELIVER) != 0
	|| process_spawn(AEM_PROCESSTYPE_ACCOUNT) != 0
	) {
		wipeKeys();
		syslog(LOG_ERR, "Failed starting T2 processes");
		return -1;
	}

	bzero(aemPid, sizeof(aemPid));

	while (!terminate) {
		const int sockClient = accept4(sockMain, NULL, NULL, SOCK_CLOEXEC); // fd=1
		if (sockClient < 0) continue;
		respond_manager(sockClient);

//		if (!verifyStatus()) {
//			killAll(SIGUSR1);
//			return 100;
//		}
	}

	close(sockMain);
	wipeKeys();
	return 0;
}
