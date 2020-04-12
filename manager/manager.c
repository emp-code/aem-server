/*
	All-Ears Manager

	Protocol:
		All messages are AEM_LEN_MSG bytes in cleartext, and are encrypted with crypto_secretbox_easy

		1. Client sends message containing instructions (if any)
		2. Server processes instructions, if any (spawn/terminate/kill an All-Ears process)
		3. Server responds with message containing information about All-Ears processes

	The encryption is mostly for authentication. There is no forward secrecy.
*/

#define _GNU_SOURCE // for pipe2(), accept4

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/securebits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "../Global.h"

#include "global.h"
#include "mount.h"

#include "manager.h"

#define AEM_SOCKET_TIMEOUT 10

#define AEM_MAXPROCESSES 25
#define AEM_LEN_MSG 1024 // must be at least AEM_MAXPROCESSES * 3 * 4
#define AEM_LEN_ENCRYPTED (AEM_LEN_MSG + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
#define AEM_STACKSIZE 1048576 // 1 MiB

#define AEM_PATH_CONF "/etc/allears"
#define AEM_PATH_KEY_ACC AEM_PATH_CONF"/Account.key"
#define AEM_PATH_KEY_API AEM_PATH_CONF"/API.key"
#define AEM_PATH_KEY_MNG AEM_PATH_CONF"/Manager.key"
#define AEM_PATH_KEY_STI AEM_PATH_CONF"/Stindex.key"
#define AEM_PATH_KEY_STO AEM_PATH_CONF"/Storage.key"

#define AEM_PATH_SLT_NRM AEM_PATH_CONF"/Normal.slt"
#define AEM_PATH_SLT_SHD AEM_PATH_CONF"/Shield.slt"

#define AEM_PATH_TLS_CRT AEM_PATH_CONF"/TLS.crt"
#define AEM_PATH_TLS_KEY AEM_PATH_CONF"/TLS.key"

#define AEM_PATH_HTML AEM_PATH_CONF"/index.html"

#define AEM_LEN_FILE_MAX 8192

static unsigned char master[AEM_LEN_KEY_MASTER];

static unsigned char accessKey_account_api[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_account_mta[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage_api[AEM_LEN_ACCESSKEY];
static unsigned char accessKey_storage_mta[AEM_LEN_ACCESSKEY];

static unsigned char key_acc[AEM_LEN_KEY_ACC];
static unsigned char key_api[AEM_LEN_KEY_API];
static unsigned char key_mng[AEM_LEN_KEY_MNG];
static unsigned char key_sti[AEM_LEN_KEY_STI];
static unsigned char key_sto[AEM_LEN_KEY_STO];

static unsigned char slt_nrm[AEM_LEN_SALT_ADDR];
static unsigned char slt_shd[AEM_LEN_SALT_ADDR];

static unsigned char tls_crt[AEM_LEN_FILE_MAX];
static unsigned char tls_key[AEM_LEN_FILE_MAX];
static size_t len_tls_crt;
static size_t len_tls_key;

static unsigned char html[AEM_LEN_FILE_MAX];
static size_t len_html;

struct aem_process {
	pid_t pid;
	unsigned char *stack;
};

static struct aem_process aemProc[3][AEM_MAXPROCESSES];

static pid_t pid_account = 0;
static pid_t pid_storage = 0;
static unsigned char *stack_account;
static unsigned char *stack_storage;

static unsigned char encrypted[AEM_LEN_ENCRYPTED];
static unsigned char decrypted[AEM_LEN_MSG];

static int sockMain = -1;
static int sockClient = -1;

static bool terminate = false;

// For handling large writes on O_DIRECT pipes
static int pipeWriteDirect(const int fd, const unsigned char * const data, const size_t len) {
	size_t written = 0;

	while (len - written > PIPE_BUF) {
		const ssize_t ret = write(fd, data + written, len - written);
		if (ret < 1) return -1;
		written += len;
	}

	return write(fd, data + written, len - written);
}

void setMasterKey(const unsigned char newKey[crypto_secretbox_KEYBYTES]) {
	memcpy(master, newKey, crypto_secretbox_KEYBYTES);
}

void setAccessKeys(void) {
	randombytes_buf(accessKey_account_api, AEM_LEN_ACCESSKEY);
	randombytes_buf(accessKey_account_mta, AEM_LEN_ACCESSKEY);
	randombytes_buf(accessKey_storage_api, AEM_LEN_ACCESSKEY);
	randombytes_buf(accessKey_storage_mta, AEM_LEN_ACCESSKEY);
}

void wipeKeys(void) {
	sodium_memzero(master, AEM_LEN_KEY_MASTER);

	sodium_memzero(accessKey_account_api, AEM_LEN_ACCESSKEY);
	sodium_memzero(accessKey_account_mta, AEM_LEN_ACCESSKEY);
	sodium_memzero(accessKey_storage_api, AEM_LEN_ACCESSKEY);
	sodium_memzero(accessKey_storage_mta, AEM_LEN_ACCESSKEY);

	sodium_memzero(key_acc, AEM_LEN_KEY_ACC);
	sodium_memzero(key_api, AEM_LEN_KEY_API);
	sodium_memzero(key_mng, AEM_LEN_KEY_MNG);
	sodium_memzero(key_sto, AEM_LEN_KEY_STO);

	sodium_memzero(slt_nrm, AEM_LEN_SALT_ADDR);
	sodium_memzero(slt_shd, AEM_LEN_SALT_ADDR);

	sodium_memzero(tls_crt, len_tls_crt);
	sodium_memzero(tls_key, len_tls_key);

	sodium_memzero(html, len_html);

	len_tls_crt = 0;
	len_tls_key = 0;
	len_html = 0;

	sodium_memzero(encrypted, AEM_LEN_ENCRYPTED);
	sodium_memzero(decrypted, AEM_LEN_MSG);
}

static bool process_verify(const pid_t pid) {
	if (pid < 1) return false;

	char path[22];
	sprintf(path, "/proc/%u/stat", pid);
	const int fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) return false;

	char buf[41];
	const off_t bytes = read(fd, buf, 41);
	close(fd);
	if (bytes < 41) return false;

	const char *c = memchr(buf, ' ', 41);
	if (c == NULL || c - buf > 11) return false;
	c++;
	if (*c != '(') return false;

	c = strchr(c + 1, ' ');
	if (c == NULL || c - buf > 29) return false;
	c++;
	if (*c != 'R' && *c != 'S') return false;
	c++;
	if (*c != ' ') return false;
	c++;

	if (strtol(c, NULL, 10) != getpid()) return false;

	return true;
}

static void refreshPids(void) {
	for (int type = 0; type < 3; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (!process_verify(aemProc[type][i].pid)) {
				deleteMount(aemProc[type][i].pid, type);
				free(aemProc[type][i].stack);
				aemProc[type][i].pid = 0;
			}
		}
	}

	if (!process_verify(pid_account)) {
		deleteMount(pid_account, AEM_PROCESSTYPE_ACCOUNT);
		pid_account = 0;
	}

	if (!process_verify(pid_storage)) {
		deleteMount(pid_storage, AEM_PROCESSTYPE_STORAGE);
		pid_storage = 0;
	}

}

// SIGUSR1 = Allow processing one more connection; SIGUSR2 = Immediate termination
void killAll(int sig) {
	wipeKeys();
	refreshPids();

	if (sig != SIGUSR1 && sig != SIGUSR2) sig = SIGUSR1;

	for (int type = 0; type < 3; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemProc[type][i].pid > 0) kill(aemProc[type][i].pid, sig); // Request process to terminate
		}
	}

	if (sig == SIGUSR1) {
		// TODO: Connect to each service to make sure they'll terminate
	} else {
		if (pid_account > 0) kill(pid_account, SIGUSR2);
		if (pid_storage > 0) kill(pid_storage, SIGUSR2);
	}

	// Processes should have terminated after one second
	sleep(1);
	refreshPids();

	if (sig == SIGUSR1) {
		for (int type = 0; type < 3; type++) {
			for (int i = 0; i < AEM_MAXPROCESSES; i++) {
				if (aemProc[type][i].pid > 0) kill(aemProc[type][i].pid, SIGUSR2);
			}
		}

		if (pid_account > 0) kill(pid_account, SIGUSR1);
		if (pid_storage > 0) kill(pid_storage, SIGUSR1);

		sleep(1);
		refreshPids();
	}

	for (int type = 0; type < 3; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemProc[type][i].pid > 0) kill(aemProc[type][i].pid, SIGKILL);
		}
	}

	if (pid_account > 0) kill(pid_account, SIGUSR2);
	if (pid_storage > 0) kill(pid_storage, SIGUSR2);

	sleep(1);
	refreshPids();
	if (pid_account > 0) kill(pid_account, SIGKILL);
	if (pid_storage > 0) kill(pid_storage, SIGKILL);

	rmdir(AEM_CHROOT);
	exit(EXIT_SUCCESS);
}

static int loadFile(const char * const path, unsigned char * const target, size_t * const len, const off_t expectedLen) {
	const int fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) return -1;

	off_t bytes = lseek(fd, 0, SEEK_END);
	if (bytes < 1 || bytes > AEM_LEN_FILE_MAX - crypto_secretbox_NONCEBYTES || (expectedLen != 0 && bytes != expectedLen + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)) {close(fd); return -1;}
	lseek(fd, 0, SEEK_SET);

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	off_t readBytes = read(fd, nonce, crypto_secretbox_NONCEBYTES);
	if (readBytes != crypto_secretbox_NONCEBYTES) {close(fd); return -1;}
	bytes -= crypto_secretbox_NONCEBYTES;

	unsigned char enc[bytes];
	readBytes = read(fd, enc, bytes);
	close(fd);
	if (readBytes != bytes) return -1;

	if (len != NULL) *len = bytes - crypto_secretbox_MACBYTES;

	return crypto_secretbox_open_easy(target, enc, bytes, nonce, master);
}

int loadFiles(void) {
	return (
	   loadFile(AEM_PATH_KEY_ACC, key_acc, NULL, AEM_LEN_KEY_ACC) == 0
	&& loadFile(AEM_PATH_KEY_API, key_api, NULL, AEM_LEN_KEY_API) == 0
	&& loadFile(AEM_PATH_KEY_MNG, key_mng, NULL, AEM_LEN_KEY_MNG) == 0
	&& loadFile(AEM_PATH_KEY_STO, key_sto, NULL, AEM_LEN_KEY_STO) == 0

	&& loadFile(AEM_PATH_SLT_NRM, slt_nrm, NULL, AEM_LEN_SALT_ADDR) == 0
	&& loadFile(AEM_PATH_SLT_SHD, slt_shd, NULL, AEM_LEN_SALT_ADDR) == 0

	&& loadFile(AEM_PATH_TLS_CRT, tls_crt, &len_tls_crt, 0) == 0
	&& loadFile(AEM_PATH_TLS_KEY, tls_key, &len_tls_key, 0) == 0

	&& loadFile(AEM_PATH_HTML, html, &len_html, 0) == 0
	) ? 0 : -1;
}

static int setCaps(const int type) {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_WEB) {
		// Make CAP_NET_BIND_SERVICE ambient
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)                != 0) return -1;
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0) != 0) return -1;

		// Allow changing SecureBits for the next part
		const cap_value_t capPcap = CAP_SETPCAP;
		cap_t caps = cap_get_proc();
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &capPcap, CAP_SET) != 0 || cap_set_proc(caps) != 0) return -1;

		// Disable and lock further ambient caps
		if (prctl(PR_SET_SECUREBITS, SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED | SECBIT_NOROOT | SECURE_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED) != 0) {
			syslog(LOG_ERR, "Failed setting SecureBits");
			return -1;
		}

		// Disable all but the one capability needed
		const cap_value_t capBind = CAP_NET_BIND_SERVICE;
		return (
			cap_clear(caps) == 0
		&& cap_set_flag(caps, CAP_INHERITABLE, 1, &capBind, CAP_SET) == 0
		&& cap_set_flag(caps, CAP_PERMITTED, 1, &capBind, CAP_SET) == 0
		&& cap_set_flag(caps, CAP_EFFECTIVE, 1, &capBind, CAP_SET) == 0
		&& cap_set_proc(caps) == 0
		&& cap_free(caps) == 0
		) ? 0 : -1;
	} else if (type == AEM_PROCESSTYPE_ACCOUNT || type == AEM_PROCESSTYPE_STORAGE) {
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) return -1;

		// Allow changing SecureBits for the next part
		const cap_value_t capPcap = CAP_SETPCAP;
		cap_t caps = cap_get_proc();
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &capPcap, CAP_SET) != 0 || cap_set_proc(caps) != 0) return -1;

		if (prctl(PR_SET_SECUREBITS, SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED | SECBIT_NOROOT | SECURE_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED) != 0) {
			syslog(LOG_ERR, "Failed setting SecureBits");
			return -1;
		}

		return (
			cap_clear(caps) == 0
		&& cap_set_proc(caps) == 0
		&& cap_free(caps) == 0
		) ? 0 : -1;
	}

	return -1;
}

static int setSubLimits(const int type) {
	struct rlimit rlim;

	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_WEB) {
		rlim.rlim_cur = 0;
		rlim.rlim_max = 0;
		if (setrlimit(RLIMIT_FSIZE, &rlim) != 0) return -1;
	}

	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT: rlim.rlim_cur = 4; rlim.rlim_max = 4; break;
		case AEM_PROCESSTYPE_STORAGE: rlim.rlim_cur = 5; rlim.rlim_max = 5; break;

		case AEM_PROCESSTYPE_MTA: rlim.rlim_cur = 4; rlim.rlim_max = 4; break;
		case AEM_PROCESSTYPE_API: rlim.rlim_cur = 4; rlim.rlim_max = 4; break;
		case AEM_PROCESSTYPE_WEB: rlim.rlim_cur = 3; rlim.rlim_max = 3; break;
	}

	if (setrlimit(RLIMIT_OFILE, &rlim) != 0) return -1;

	return 0;
}

__attribute__((warn_unused_result))
static int dropRoot(const pid_t pid) {
	char dir[50];
	sprintf(dir, AEM_CHROOT"/%d", pid);
	const struct passwd * const p = getpwnam("allears");

	return (
	   p != NULL

	&& chroot(dir) == 0
	&& chdir("/") == 0

	&& setgroups(0, NULL) == 0
	&& setgid(p->pw_gid) == 0
	&& setuid(p->pw_uid) == 0

	&& getgid() == p->pw_gid
	&& getuid() == p->pw_uid
	) ? 0 : -1;
}

static int process_new(void *params) {
	wipeKeys();
	close(sockMain);
	close(sockClient);

	pid_t pid = getpid();
	const int type = ((uint8_t*)params)[0];
	const int pipefd = ((uint8_t*)params)[1];

	if (prctl(PR_SET_PDEATHSIG, SIGUSR2, 0, 0, 0) != 0) {syslog(LOG_ERR, "Failed prctl()"); exit(EXIT_FAILURE);}
	if (createMount(pid, type, pid_account, pid_storage) != 0) {syslog(LOG_ERR, "Failed createMount()"); exit(EXIT_FAILURE);}
	if (setSubLimits(type) != 0) {syslog(LOG_ERR, "Failed setSubLimits()"); exit(EXIT_FAILURE);}
	if (dropRoot(pid) != 0) {syslog(LOG_ERR, "Failed dropRoot()"); exit(EXIT_FAILURE);}
	if (setCaps(type) != 0) {syslog(LOG_ERR, "Failed setCaps()"); exit(EXIT_FAILURE);}

	char arg1[] = {pipefd, '\0'};
	char * const newargv[] = {arg1, NULL};

	switch (type) {
		case AEM_PROCESSTYPE_ACCOUNT: execv("usr/bin/allears-account", newargv); break;
		case AEM_PROCESSTYPE_STORAGE: execv("usr/bin/allears-storage", newargv); break;

		case AEM_PROCESSTYPE_WEB: execv("usr/bin/allears-web", newargv); break;
		case AEM_PROCESSTYPE_API: execv("usr/bin/allears-api", newargv); break;
		case AEM_PROCESSTYPE_MTA: execv("usr/bin/allears-mta", newargv); break;
	}

	// Only runs if exec failed
	syslog(LOG_ERR, "Failed starting process");
	return 0;
}

static void process_spawn(const int type) {
	int freeSlot = -1;
	unsigned char *stack;

	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_WEB) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (aemProc[type][i].pid == 0) {
				freeSlot = i;
				break;
			}
		}

		if (freeSlot < 0) return;
	}

	stack = calloc(AEM_STACKSIZE, 1);
	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_WEB) {
		aemProc[type][freeSlot].stack = stack;
	} else if (type == AEM_PROCESSTYPE_ACCOUNT) {
		stack_account = stack;
	} else if (type == AEM_PROCESSTYPE_STORAGE) {
		stack_storage = stack;
	}

	int fd[2];
	if (pipe2(fd, O_DIRECT) < 0) return;

	uint8_t params[] = {type, fd[0]};
	pid_t pid = clone(process_new, stack + AEM_STACKSIZE, CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_UNTRACED, params, NULL, NULL, NULL); // CLONE_CLEAR_SIGHAND (Linux>=5.5)
	if (pid < 0) return;

	close(fd[0]);

	switch(type) {
		case AEM_PROCESSTYPE_ACCOUNT:
			if (
			   pipeWriteDirect(fd[1], key_acc, AEM_LEN_KEY_ACC) < 0

			|| pipeWriteDirect(fd[1], slt_nrm, AEM_LEN_SALT_ADDR) < 0
			|| pipeWriteDirect(fd[1], slt_shd, AEM_LEN_SALT_ADDR) < 0

			|| pipeWriteDirect(fd[1], accessKey_account_api, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_account_mta, AEM_LEN_ACCESSKEY) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_STORAGE:
			if (
			   pipeWriteDirect(fd[1], key_sti, AEM_LEN_KEY_STI) < 0
			|| pipeWriteDirect(fd[1], key_sto, AEM_LEN_KEY_STO) < 0

			|| pipeWriteDirect(fd[1], accessKey_storage_api, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_storage_mta, AEM_LEN_ACCESSKEY) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_API:
			if (
			   pipeWriteDirect(fd[1], (unsigned char*)&pid_account, sizeof(pid_t)) < 0
			|| pipeWriteDirect(fd[1], (unsigned char*)&pid_storage, sizeof(pid_t)) < 0

			|| pipeWriteDirect(fd[1], key_api, AEM_LEN_KEY_API) < 0
			|| pipeWriteDirect(fd[1], accessKey_account_api, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_storage_api, AEM_LEN_ACCESSKEY) < 0

			|| pipeWriteDirect(fd[1], tls_crt, len_tls_crt) < 0
			|| pipeWriteDirect(fd[1], tls_key, len_tls_key) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_MTA:
			if (
			   pipeWriteDirect(fd[1], (unsigned char*)&pid_account, sizeof(pid_t)) < 0
			|| pipeWriteDirect(fd[1], (unsigned char*)&pid_storage, sizeof(pid_t)) < 0

			|| pipeWriteDirect(fd[1], accessKey_account_mta, AEM_LEN_ACCESSKEY) < 0
			|| pipeWriteDirect(fd[1], accessKey_storage_mta, AEM_LEN_ACCESSKEY) < 0

			|| pipeWriteDirect(fd[1], tls_crt, len_tls_crt) < 0
			|| pipeWriteDirect(fd[1], tls_key, len_tls_key) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;

		case AEM_PROCESSTYPE_WEB:
			if (
			   pipeWriteDirect(fd[1], tls_crt, len_tls_crt) < 0
			|| pipeWriteDirect(fd[1], tls_key, len_tls_key) < 0
			|| pipeWriteDirect(fd[1], html, len_html) < 0
			) syslog(LOG_ERR, "Failed writing to pipe: %m");
		break;
	}

	close(fd[1]);

	if (type == AEM_PROCESSTYPE_MTA || type == AEM_PROCESSTYPE_API || type == AEM_PROCESSTYPE_WEB) {
		aemProc[type][freeSlot].pid = pid;
	}
	else if (type == AEM_PROCESSTYPE_ACCOUNT) pid_account = pid;
	else if (type == AEM_PROCESSTYPE_STORAGE) pid_storage = pid;

}

static void process_kill(const int type, const pid_t pid, const int sig) {
	syslog(LOG_INFO, "Termination of process %d requested", pid);
	if (type < 0 || type > 2 || pid < 1) return;

	bool found = false;
	for (int i = 0; i < AEM_MAXPROCESSES; i++) {
		if (aemProc[type][i].pid == pid) {
			found = true;
			break;
		}
	}

	if (!found) {syslog(LOG_INFO, "Process %d was not found", pid); return;}
	if (!process_verify(pid)) {syslog(LOG_INFO, "Process %d not valid", pid); return;}

	kill(pid, sig);
}

void cryptSend(const int sock) {
	refreshPids();

	bzero(decrypted, AEM_LEN_MSG);

	for (int i = 0; i < 3; i++) {
		for (int j = 0; j < AEM_MAXPROCESSES; j++) {
			const int start = ((i * AEM_MAXPROCESSES) + j) * 4;
			memcpy(decrypted + start, &(aemProc[i][j].pid), 4);
		}
	}

	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, decrypted, AEM_LEN_MSG, encrypted, key_mng);
	send(sock, encrypted, AEM_LEN_ENCRYPTED, 0);
}

static void respond_manager(const int sock) {
	while (recv(sock, encrypted, AEM_LEN_ENCRYPTED, 0) == AEM_LEN_ENCRYPTED) {
		if (crypto_secretbox_open_easy(decrypted, encrypted + crypto_secretbox_NONCEBYTES, AEM_LEN_ENCRYPTED - crypto_secretbox_NONCEBYTES, encrypted, key_mng) != 0) return;

		switch(decrypted[0]) {
			case '\0': break; // No action, only requesting info

			case 'T': { // Request termination
				uint32_t pid;
				memcpy(&pid, decrypted + 2, 4);
				process_kill(decrypted[1], pid, SIGUSR1);
				break;
			}

			case 'K': { // Request immediate termination (kill)
				uint32_t pid;
				memcpy(&pid, decrypted + 2, 4);
				process_kill(decrypted[1], pid, SIGUSR2);
				break;
			}

			case 'S': { // Spawn
				process_spawn(decrypted[1]);
				break;
			}

			default: return; // Invalid command
		}

		cryptSend(sock);
	}
}

__attribute__((warn_unused_result))
static int initSocket(const int * const sock, const int port) {
	struct sockaddr_in servAddr;
	bzero((char*)&servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	const int ret = bind(*sock, (struct sockaddr*)&servAddr, sizeof(servAddr));
	if (ret < 0) return ret;

	listen(*sock, 3); // socket, backlog (# of connections to keep in queue)
	return 0;
}

static void setSocketTimeout(const int sock) {
	struct timeval tv;
	tv.tv_sec = AEM_SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
}

int receiveConnections(void) {
	setAccessKeys();
	process_spawn(AEM_PROCESSTYPE_ACCOUNT);
	process_spawn(AEM_PROCESSTYPE_STORAGE);

	sockMain = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sockMain < 0) {wipeKeys(); return EXIT_FAILURE;}

	if (initSocket(&sockMain, AEM_PORT_MANAGER) != 0) {wipeKeys(); return EXIT_FAILURE;}

	while (!terminate) {
		sockClient = accept4(sockMain, NULL, NULL, SOCK_CLOEXEC);
		if (sockClient < 0) break;
		setSocketTimeout(sockClient);
		respond_manager(sockClient);
		close(sockClient);
	}

	close(sockMain);
	wipeKeys();
	return EXIT_SUCCESS;
}
