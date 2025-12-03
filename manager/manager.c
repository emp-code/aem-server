#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/sched.h>
#include <linux/securebits.h>
#include <pwd.h>
#include <signal.h>
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
#include "../Common/x509_getCn.h"
#include "../IntCom/KeyBundle.h"

#include "mount.h"

#include "manager.h"

#define AEM_FD_EXEC     AEM_FD_SOCK_MAIN // 1
#define AEM_FD_READFILE AEM_FD_PIPE_WR   // 3

enum intcom_keynum {
	AEM_KEYNUM_INTCOM_NULL,
	AEM_KEYNUM_INTCOM_ACCOUNT_API,
	AEM_KEYNUM_INTCOM_ACCOUNT_MTA,
	AEM_KEYNUM_INTCOM_ACCOUNT_REG,
	AEM_KEYNUM_INTCOM_ACCOUNT_STO,
	AEM_KEYNUM_INTCOM_ENQUIRY_API,
	AEM_KEYNUM_INTCOM_ENQUIRY_DLV,
	AEM_KEYNUM_INTCOM_STORAGE_ACC,
	AEM_KEYNUM_INTCOM_STORAGE_API,
	AEM_KEYNUM_INTCOM_STORAGE_DLV,
	AEM_KEYNUM_INTCOM_STREAM
};

static unsigned char key_mng[crypto_aead_aegis256_KEYBYTES];
static unsigned char key_ic[AEM_KDF_SMK_KEYLEN]; // Randomly generated master key used to derive IntCom keys through AEM_KDF_SMK

static const int typeNice[AEM_PROCESSTYPES_COUNT] = AEM_NICE;

static pid_t pid_acc = 0;
static pid_t pid_dlv = 0;
static pid_t pid_enq = 0;
static pid_t pid_sto = 0;
static pid_t pid_reg = 0;
static pid_t pid_web = 0;

static pid_t pid_api[AEM_MAXPROCESSES];
static pid_t pid_mta[AEM_MAXPROCESSES];
static bool uds_api[AEM_MAXPROCESSES];

static volatile sig_atomic_t terminate = 0;

__attribute__((warn_unused_result))
static uint8_t avail_uds_api(void) {
	for (int i = 0; i < AEM_MAXPROCESSES; i++) {
		if (!uds_api[i]) return i;
	}

	return UINT8_MAX;
}

__attribute__((warn_unused_result))
static bool process_exists(const pid_t pid) {
	return (pid < 1) ? false : kill(pid, 0) == 0;
}

static void refreshPids(void) {
	for (int i = 0; i < AEM_MAXPROCESSES; i++) {
		if (pid_api[i] != 0 && !process_exists(pid_api[i])) {
			pid_api[i] = 0;
			uds_api[i] = false;
		}

		if (pid_mta[i] != 0 && !process_exists(pid_mta[i])) {
			pid_mta[i] = 0;
		}
	}

	if (pid_acc != 0 && !process_exists(pid_acc)) pid_acc = 0;
	if (pid_dlv != 0 && !process_exists(pid_dlv)) pid_dlv = 0;
	if (pid_enq != 0 && !process_exists(pid_enq)) pid_enq = 0;
	if (pid_sto != 0 && !process_exists(pid_sto)) pid_sto = 0;
	if (pid_reg != 0 && !process_exists(pid_reg)) pid_reg = 0;
	if (pid_web != 0 && !process_exists(pid_web)) pid_web = 0;
}

static void killAll(const int sig) {
	if (pid_acc > 0) kill(pid_acc, sig);
	if (pid_dlv > 0) kill(pid_dlv, sig);
	if (pid_enq > 0) kill(pid_enq, sig);
	if (pid_sto > 0) kill(pid_sto, sig);

	for (int i = 0; i < AEM_MAXPROCESSES; i++) {
		if (pid_api[i] > 0) kill(pid_api[i], sig);
		if (pid_mta[i] > 0) kill(pid_mta[i], sig);
	}
}

__attribute__((warn_unused_result))
static int loadExec(const int type, const unsigned char * const launchKey) {
	if (memfd_create("aem", MFD_CLOEXEC | MFD_ALLOW_SEALING) != AEM_FD_EXEC) {
		syslog(LOG_ERR, "Failed memfd_create: %m");
		return -1;
	}

	const char * const path[] = AEM_PATH_EXE;
	const int fd = open(path[type], O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd != AEM_FD_READFILE || !validFd(fd)) {syslog(LOG_ERR, "Failed opening file: %s", path[type]); close(AEM_FD_EXEC); return -1;}

	const off_t bytes = lseek(fd, 0, SEEK_END);
	if (bytes < 1 || bytes > AEM_MAXLEN_EXEC) {
		syslog(LOG_ERR, "Invalid length on %s", path[type]);
		close(AEM_FD_EXEC);
		close(fd);
		return -1;
	}

	unsigned char enc[bytes];
	if (pread(fd, enc, bytes, 0) != bytes) {
		syslog(LOG_ERR, "Failed reading %s: %m", path[type]);
		close(AEM_FD_EXEC);
		close(fd);
		return -1;
	}
	close(fd);

	const size_t lenDec = bytes - crypto_aead_aegis256_NPUBBYTES - crypto_aead_aegis256_ABYTES;
	unsigned char dec[lenDec];
	if (crypto_aead_aegis256_decrypt(dec, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, bytes - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, launchKey) == -1) {
		syslog(LOG_ERR, "Failed decrypting %s (size %d)", path[type], bytes);
		close(AEM_FD_EXEC);
		return -1;
	}

	if (
	   write(AEM_FD_EXEC, dec, lenDec) != (ssize_t)lenDec
	|| fcntl(AEM_FD_EXEC, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0
	) {
		syslog(LOG_ERR, "Failed loadExec: %m");
		close(AEM_FD_EXEC);
		return -1;
	}

	return 0;
}

__attribute__((nonnull, warn_unused_result))
static int readDataFile(unsigned char * const dec, size_t * const lenDec, const char * const path, const unsigned char * const launchKey) {
	const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0 || !validFd(fd)) {
		syslog(LOG_ERR, "Failed opening file: %s", path);
		return -1;
	}

	const off_t lenEnc = lseek(fd, 0, SEEK_END);
	if (lenEnc < 1 + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES || lenEnc > AEM_MAXLEN_DATAFILE) {
		syslog(LOG_ERR, "Invalid length on %s: %u", path, lenEnc);
		close(fd);
		return -1;
	}

	unsigned char enc[lenEnc];
	if (pread(fd, enc, lenEnc, 0) != lenEnc) {
		syslog(LOG_ERR, "Failed reading %s: %m", path);
		close(fd);
		return -1;
	}
	close(fd);

	*lenDec = lenEnc - crypto_aead_aegis256_NPUBBYTES - crypto_aead_aegis256_ABYTES;
	if (crypto_aead_aegis256_decrypt(dec, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, lenEnc - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, launchKey) == -1) {
		syslog(LOG_ERR, "Failed decrypting %s (size %d)", path, lenEnc);
		return -1;
	}

	return 0;
}

__attribute__((nonnull, warn_unused_result))
static int getOurDomain(unsigned char * const out, size_t * const lenOut, const unsigned char * const launchKey) {
	size_t lenPem;
	unsigned char pem[AEM_MAXLEN_DATAFILE];
	if (readDataFile(pem, &lenPem, AEM_PATH_DATA"/TLS.crt.enc", launchKey) != 0) return -1;
	return x509_getSubject(out, lenOut, pem, lenPem);
}

__attribute__((nonnull, warn_unused_result))
static int pipeFile(const char * const path, const unsigned char * const launchKey) {
	size_t lenData;
	unsigned char data[AEM_MAXLEN_DATAFILE];
	if (readDataFile(data, &lenData, path, launchKey) != 0) return -1;

	if (write(AEM_FD_PIPE_WR, (const unsigned char*)&lenData, sizeof(size_t)) != sizeof(size_t)) {
		syslog(LOG_ERR, "pipeFile: Failed writing size");
		return -1;
	}

	size_t tbw = lenData;
	while (tbw > 0) {
		if (tbw > PIPE_BUF) {
			if (write(AEM_FD_PIPE_WR, data + (lenData - tbw), PIPE_BUF) != PIPE_BUF) return -1;
			tbw -= PIPE_BUF;
		} else {
			if (write(AEM_FD_PIPE_WR, data + (lenData - tbw), tbw) != (ssize_t)tbw) return -1;
			break;
		}
	}

	return 0;
}

__attribute__((warn_unused_result))
static int setCaps(const int type) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	// Ambient capabilities
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) return -1;

	cap_value_t cap[4];
	cap[0] = CAP_SYS_ADMIN;
	cap[1] = CAP_SYS_CHROOT;
	int numCaps;

	switch (type) {
		case AEM_PROCESSTYPE_ACC:
		case AEM_PROCESSTYPE_DLV:
		case AEM_PROCESSTYPE_ENQ:
		case AEM_PROCESSTYPE_STO:
		case AEM_PROCESSTYPE_API:
		case AEM_PROCESSTYPE_REG:
		case AEM_PROCESSTYPE_WEB:
			numCaps = 2;
		break;

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
	|| (numCaps > 2 && prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap[2], 0, 0) != 0)
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

__attribute__((warn_unused_result))
static int setLimits(const int type) {
	struct rlimit rlim;

	if (type != AEM_PROCESSTYPE_ACC && type != AEM_PROCESSTYPE_STO) {
		rlim.rlim_cur = 0;
		rlim.rlim_max = 0;
		if (setrlimit(RLIMIT_FSIZE, &rlim) != 0) return -1;
	}

	switch (type) {
		case AEM_PROCESSTYPE_ENQ: rlim.rlim_cur = 15; break;

		case AEM_PROCESSTYPE_ACC:
		case AEM_PROCESSTYPE_DLV:
		case AEM_PROCESSTYPE_STO:
		case AEM_PROCESSTYPE_MTA:
		case AEM_PROCESSTYPE_REG:
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

__attribute__((warn_unused_result))
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

__attribute__((warn_unused_result))
static int process_new(const int type, unsigned char * const launchKey) {
	sodium_memzero(key_ic, AEM_KDF_SMK_KEYLEN);
	sodium_memzero(key_mng, crypto_aead_aegis256_KEYBYTES);
	close(AEM_FD_SOCK_MAIN); // Reused as AEM_FD_EXEC
	close(AEM_FD_PIPE_WR); // Reused as AEM_FD_READFILE

	if (loadExec(type, launchKey) != 0) exit(EXIT_FAILURE);
	sodium_memzero(launchKey, crypto_aead_aegis256_KEYBYTES);
	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, "") != 0) {syslog(LOG_ERR, "[%d] Failed private mount", type); exit(EXIT_FAILURE);} // With CLONE_NEWNS, prevent propagation of mount events to other mount namespaces
	if (setpriority(PRIO_PROCESS, 0, typeNice[type])    != 0) {syslog(LOG_ERR, "[%d] Failed setpriority()", type); exit(EXIT_FAILURE);}
	if (cgroupMove()      != 0) {syslog(LOG_ERR, "[%d] Failed cgroupMove()",  type); exit(EXIT_FAILURE);}
	if (createMount(type) != 0) {syslog(LOG_ERR, "[%d] Failed createMount()", type); exit(EXIT_FAILURE);} // Opens AEM_FD_ROOT, for undoing the chroot in the new process
	close(AEM_FD_SYSLOG);
	if (setLimits(type)   != 0) {syslog(LOG_ERR, "[%d] Failed setLimits()",    type); exit(EXIT_FAILURE);}
	if (dropRoot()        != 0) {syslog(LOG_ERR, "[%d] Failed dropRoot(): %m", type); exit(EXIT_FAILURE);}
	if (setCaps(type)     != 0) {syslog(LOG_ERR, "[%d] Failed setCaps()",      type); exit(EXIT_FAILURE);}
	umask((type == AEM_PROCESSTYPE_STO) ? 0077 : 0777);

	fexecve(AEM_FD_EXEC, (char*[]){NULL}, (char*[]){NULL});

	// Only runs if exec failed
	close_range(0, UINT_MAX, 0);
	syslog(LOG_ERR, "[%d] Failed starting process: %m", type);
	exit(EXIT_FAILURE);
}

__attribute__((warn_unused_result))
static int sendIntComKeys(const int type) {
	struct intcom_keyBundle bundle;
	bzero(&bundle, sizeof(struct intcom_keyBundle));

	switch (type) {
		case AEM_PROCESSTYPE_WEB:
			return 0;

		case AEM_PROCESSTYPE_ACC:
			aem_kdf_smk(bundle.server[AEM_INTCOM_CLIENT_API], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_API, key_ic);
			aem_kdf_smk(bundle.server[AEM_INTCOM_CLIENT_MTA], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_MTA, key_ic);
			aem_kdf_smk(bundle.server[AEM_INTCOM_CLIENT_STO], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_STO, key_ic);
			aem_kdf_smk(bundle.server[AEM_INTCOM_CLIENT_REG], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_REG, key_ic);
			aem_kdf_smk(bundle.client[AEM_INTCOM_SERVER_STO], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_ACC, key_ic);
		break;

		case AEM_PROCESSTYPE_DLV:
			aem_kdf_smk(bundle.client[AEM_INTCOM_SERVER_ENQ], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_DLV, key_ic);
			aem_kdf_smk(bundle.client[AEM_INTCOM_SERVER_STO], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_DLV, key_ic);
			aem_kdf_smk(bundle.stream,       crypto_secretstream_xchacha20poly1305_KEYBYTES, AEM_KEYNUM_INTCOM_STREAM,      key_ic);
		break;

		case AEM_PROCESSTYPE_ENQ:
			aem_kdf_smk(bundle.server[AEM_INTCOM_CLIENT_API], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_API, key_ic);
			aem_kdf_smk(bundle.server[AEM_INTCOM_CLIENT_DLV], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_DLV, key_ic);
		break;

		case AEM_PROCESSTYPE_STO:
			aem_kdf_smk(bundle.server[AEM_INTCOM_CLIENT_ACC], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_ACC, key_ic);
			aem_kdf_smk(bundle.server[AEM_INTCOM_CLIENT_API], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_API, key_ic);
			aem_kdf_smk(bundle.server[AEM_INTCOM_CLIENT_DLV], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_DLV, key_ic);
			aem_kdf_smk(bundle.client[AEM_INTCOM_SERVER_ACC], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_STO, key_ic);
		break;

		case AEM_PROCESSTYPE_API:
			aem_kdf_smk(bundle.client[AEM_INTCOM_SERVER_ACC], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_API, key_ic);
			aem_kdf_smk(bundle.client[AEM_INTCOM_SERVER_ENQ], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ENQUIRY_API, key_ic);
			aem_kdf_smk(bundle.client[AEM_INTCOM_SERVER_STO], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_STORAGE_API, key_ic);
		break;

		case AEM_PROCESSTYPE_MTA:
			aem_kdf_smk(bundle.client[AEM_INTCOM_SERVER_ACC], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_MTA, key_ic);
			aem_kdf_smk(bundle.stream,       crypto_secretstream_xchacha20poly1305_KEYBYTES, AEM_KEYNUM_INTCOM_STREAM,      key_ic);
		break;

		case AEM_PROCESSTYPE_REG:
			aem_kdf_smk(bundle.client[AEM_INTCOM_SERVER_ACC], crypto_aead_aegis256_KEYBYTES, AEM_KEYNUM_INTCOM_ACCOUNT_REG, key_ic);
		break;

		default: return -1;
	}

	const ssize_t bytes = write(AEM_FD_PIPE_WR, &bundle, sizeof(bundle));
	sodium_memzero(&bundle, sizeof(bundle));
	return (bytes == sizeof(bundle))? 0 : -1;
}

__attribute__((warn_unused_result))
int process_spawn(const int type, unsigned char * const launchKey, const unsigned char *key_forward) {
	int freeSlot = -1;
	if (type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_MTA) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if ((type == AEM_PROCESSTYPE_API && pid_api[i] == 0) || (type == AEM_PROCESSTYPE_MTA && pid_mta[i] == 0)) {
				freeSlot = i;
				break;
			}
		}

		if (freeSlot == -1) return 60;
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
	if (pid == 0) exit(process_new(type, launchKey));

	close(AEM_FD_PIPE_RD); // fd1 freed

	bool fail = false;

	// Pids
	switch (type) {
		case AEM_PROCESSTYPE_ACC:
			fail = (write(AEM_FD_PIPE_WR, &pid_sto, sizeof(pid_t)) != sizeof(pid_t));
		break;

		case AEM_PROCESSTYPE_DLV:
			fail = (write(AEM_FD_PIPE_WR, (pid_t[]){pid_enq, pid_sto}, sizeof(pid_t) * 2) != sizeof(pid_t) * 2);
		break;

		case AEM_PROCESSTYPE_REG:
			fail = (write(AEM_FD_PIPE_WR, &pid_acc, sizeof(pid_t)) != sizeof(pid_t));
		break;

		case AEM_PROCESSTYPE_API:
			fail = (write(AEM_FD_PIPE_WR, (pid_t[]){pid_acc, pid_sto, pid_enq}, sizeof(pid_t) * 3) != sizeof(pid_t) * 3);
		break;

		case AEM_PROCESSTYPE_MTA:
			fail = (write(AEM_FD_PIPE_WR, (pid_t[]){pid_acc, pid_dlv}, sizeof(pid_t) * 2) != sizeof(pid_t) * 2);
		break;

		/* Nothing:
		case AEM_PROCESSTYPE_ENQ:
		case AEM_PROCESSTYPE_STO:
		case AEM_PROCESSTYPE_WEB:
		*/
	}

	if (!fail && key_forward != NULL) {
		fail = (write(AEM_FD_PIPE_WR, key_forward, AEM_KDF_SUB_KEYLEN) != AEM_KDF_SUB_KEYLEN);
	}

	if (!fail) {
		fail = (sendIntComKeys(type) != 0);
	}

	if (!fail && type == AEM_PROCESSTYPE_ACC) {
		fail = (pipeFile(AEM_PATH_DATA"/RSA_Admin.enc", launchKey) != 0 || pipeFile(AEM_PATH_DATA"/RSA_Users.enc", launchKey) != 0);
	}

	if (!fail && type == AEM_PROCESSTYPE_WEB) {
		fail = (pipeFile(AEM_PATH_DATA"/web.enc", launchKey) != 0);
	}

	if (!fail && (type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_WEB)) {
		fail = (pipeFile(AEM_PATH_DATA"/TLS.crt.enc", launchKey) != 0 || pipeFile(AEM_PATH_DATA"/TLS.key.enc", launchKey) != 0);
	}

	if (!fail && type == AEM_PROCESSTYPE_API) {
		const uint8_t udsId = avail_uds_api();
		fail = (write(AEM_FD_PIPE_WR, &udsId, 1) != 1);
		if (!fail) uds_api[udsId] = true;
	}

	close(AEM_FD_PIPE_WR);

	if (fail) {
		kill(pid, SIGKILL);
		return 63;
	}

	switch (type) {
		case AEM_PROCESSTYPE_ACC: pid_acc = pid; break;
		case AEM_PROCESSTYPE_DLV: pid_dlv = pid; break;
		case AEM_PROCESSTYPE_ENQ: pid_enq = pid; break;
		case AEM_PROCESSTYPE_STO: pid_sto = pid; break;
		case AEM_PROCESSTYPE_REG: pid_reg = pid; break;
		case AEM_PROCESSTYPE_WEB: pid_web = pid; break;
		case AEM_PROCESSTYPE_API: pid_api[freeSlot] = pid; break;
		case AEM_PROCESSTYPE_MTA: pid_mta[freeSlot] = pid; break;
	}

	return 0;
}

int process_term(const int type) {
	switch (type) {
		case AEM_PROCESSTYPE_ACC: kill(pid_acc, SIGUSR1); pid_acc = 0; break;
		case AEM_PROCESSTYPE_DLV: kill(pid_dlv, SIGUSR1); pid_dlv = 0; break;
		case AEM_PROCESSTYPE_ENQ: kill(pid_enq, SIGUSR1); pid_enq = 0; break;
		case AEM_PROCESSTYPE_STO: kill(pid_sto, SIGUSR1); pid_sto = 0; break;
		case AEM_PROCESSTYPE_REG: kill(pid_reg, SIGUSR1); pid_reg = 0; break;
		case AEM_PROCESSTYPE_WEB: kill(pid_web, SIGUSR1); pid_web = 0; break;
//		case AEM_PROCESSTYPE_API: TODO; break;
//		case AEM_PROCESSTYPE_MTA: TODO; break;
		default: syslog(LOG_WARNING, "process_term: Invalid process type");
	}

	return 0;
}

void getProcessInfo(unsigned char * const out) {
	if (kill(pid_acc, 0) == -1) pid_acc = 0;
	if (kill(pid_dlv, 0) == -1) pid_dlv = 0;
	if (kill(pid_enq, 0) == -1) pid_enq = 0;
	if (kill(pid_sto, 0) == -1) pid_sto = 0;
	if (kill(pid_reg, 0) == -1) pid_reg = 0;
	if (kill(pid_web, 0) == -1) pid_web = 0;

	bzero(out, AEM_PROCESSINFO_BYTES);

	out[0] =
	  ((pid_acc > 0) ? 128 : 0)
	| ((pid_dlv > 0) ?  64 : 0)
	| ((pid_enq > 0) ?  32 : 0)
	| ((pid_sto > 0) ?  16 : 0)
	| ((pid_reg > 0) ?   8 : 0)
	| ((pid_web > 0) ?   4 : 0);

	for (int slot = 0; slot < AEM_MAXPROCESSES; slot++) {
		if (pid_api[slot] == 0) continue;
		out[1 + (slot - (slot % 8)) / 8] |= 1 << (slot % 8);
	}

	for (int slot = 0; slot < AEM_MAXPROCESSES; slot++) {
		if (pid_mta[slot] == 0) continue;
		out[1 + (AEM_MAXPROCESSES / 8) + (slot - (slot % 8)) / 8] |= 1 << (slot % 8);
	}
}

void setupManager(void) {
	bzero(pid_api, sizeof(pid_t) * AEM_MAXPROCESSES);
	bzero(pid_mta, sizeof(pid_t) * AEM_MAXPROCESSES);
	bzero(uds_api, sizeof(bool) * AEM_MAXPROCESSES);
	randombytes_buf(key_ic, AEM_KDF_SMK_KEYLEN);
}

void clearManager(void) {
	sodium_memzero(key_ic, AEM_KDF_SMK_KEYLEN);
}
