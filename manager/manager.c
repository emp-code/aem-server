/*
	All-Ears Manager

	Protocol:
		All messages are AEM_LEN_MSG bytes in cleartext, and are encrypted with crypto_secretbox_easy

		1. Client sends message containing instructions (if any)
		2. Server processes instructions, if any (spawn/terminate/kill an All-Ears process)
		3. Server responds with message containing information about All-Ears processes

	The encryption is mostly for authentication. There is no forward secrecy.
*/

#define _GNU_SOURCE // for pipe2()

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/securebits.h>
#include <pwd.h>
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

#include "global.h"

#include "manager.h"

#define AEM_PORT_MANAGER 940
#define AEM_SOCKET_TIMEOUT 10

#define AEM_LEN_MSG 1024 // must be at least AEM_MAXPROCESSES * 3 * 4
#define AEM_LEN_ENCRYPTED (AEM_LEN_MSG + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)

#define AEM_PROCESSTYPE_MTA 0
#define AEM_PROCESSTYPE_WEB 1
#define AEM_PROCESSTYPE_API 2

#define AEM_MAXPROCESSES 25

#define AEM_PATH_CONF "/etc/allears"
#define AEM_PATH_KEY_ADR AEM_PATH_CONF"/Address.key"
#define AEM_PATH_KEY_API AEM_PATH_CONF"/API.key"
#define AEM_PATH_KEY_MNG AEM_PATH_CONF"/Manager.key"

#define AEM_PATH_TLS_CRT AEM_PATH_CONF"/TLS.crt"
#define AEM_PATH_TLS_KEY AEM_PATH_CONF"/TLS.key"

#define AEM_PATH_WEB_CSS AEM_PATH_CONF"/main.css"
#define AEM_PATH_WEB_HTM AEM_PATH_CONF"/index.html"
#define AEM_PATH_WEB_JSA AEM_PATH_CONF"/all-ears.js"
#define AEM_PATH_WEB_JSM AEM_PATH_CONF"/main.js"

#define AEM_LEN_KEY_MASTER crypto_secretbox_KEYBYTES
#define AEM_LEN_KEY_ADR crypto_pwhash_SALTBYTES
#define AEM_LEN_KEY_API crypto_box_SECRETKEYBYTES
#define AEM_LEN_KEY_MNG crypto_secretbox_KEYBYTES
#define AEM_LEN_FILE_MAX 8192

static unsigned char master[AEM_LEN_KEY_MASTER];
static unsigned char key_adr[AEM_LEN_KEY_ADR];
static unsigned char key_api[AEM_LEN_KEY_API];
static unsigned char key_mng[AEM_LEN_KEY_MNG];

static unsigned char tls_crt[AEM_LEN_FILE_MAX];
static unsigned char tls_key[AEM_LEN_FILE_MAX];
static size_t len_tls_crt;
static size_t len_tls_key;

static unsigned char web_css[AEM_LEN_FILE_MAX];
static unsigned char web_htm[AEM_LEN_FILE_MAX];
static unsigned char web_jsa[AEM_LEN_FILE_MAX];
static unsigned char web_jsm[AEM_LEN_FILE_MAX];
static size_t len_web_css;
static size_t len_web_htm;
static size_t len_web_jsa;
static size_t len_web_jsm;

static pid_t pids[3][AEM_MAXPROCESSES];

static unsigned char encrypted[AEM_LEN_ENCRYPTED];
static unsigned char decrypted[AEM_LEN_MSG];

static int sockMain;
static int sockClient;

static bool terminate = false;

void setMasterKey(const unsigned char newKey[crypto_secretbox_KEYBYTES]) {
	memcpy(master, newKey, crypto_secretbox_KEYBYTES);
}

void wipeKeys(void) {
	sodium_memzero(master, AEM_LEN_KEY_MASTER);
	sodium_memzero(key_adr, AEM_LEN_KEY_ADR);
	sodium_memzero(key_api, AEM_LEN_KEY_API);
	sodium_memzero(key_mng, AEM_LEN_KEY_MNG);

	sodium_memzero(tls_crt, len_tls_crt);
	sodium_memzero(tls_key, len_tls_key);

	sodium_memzero(web_css, len_web_css);
	sodium_memzero(web_htm, len_web_htm);
	sodium_memzero(web_jsa, len_web_jsa);
	sodium_memzero(web_jsm, len_web_jsm);

	len_tls_crt = 0;
	len_tls_key = 0;

	len_web_htm = 0;
	len_web_jsa = 0;
	len_web_jsm = 0;
	len_web_css = 0;

	sodium_memzero(encrypted, AEM_LEN_ENCRYPTED);
	sodium_memzero(decrypted, AEM_LEN_MSG);
}

static bool process_verify(const pid_t pid) {
	char path[22];
	sprintf(path, "/proc/%u/stat", pid);
	const int fd = open(path, O_RDONLY);
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
			if (!process_verify(pids[type][i])) pids[type][i] = 0;
		}
	}
}

// SIGUSR1 = Allow processing one more connection; SIGUSR2 = Immediate termination
void killAll(int sig) {
	wipeKeys();

	if (sig != SIGUSR1 && sig != SIGUSR2) sig = SIGUSR1;

	for (int type = 0; type < 3; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (pids[type][i] > 0) kill(pids[type][i], sig); // Request process to terminate
		}
	}

	if (sig == SIGUSR1) {
		// TODO: Connect to each service to make sure they'll terminate
	}

	// Processes should have terminated after one second
	sleep(1);
	refreshPids();

	if (sig == SIGUSR1) {
		for (int type = 0; type < 3; type++) {
			for (int i = 0; i < AEM_MAXPROCESSES; i++) {
				if (pids[type][i] > 0) kill(pids[type][i], SIGUSR2);
			}
		}

		sleep(1);
		refreshPids();
	}

	for (int type = 0; type < 3; type++) {
		for (int i = 0; i < AEM_MAXPROCESSES; i++) {
			if (pids[type][i] > 0) kill(pids[type][i], SIGKILL);
		}
	}

	if (sig == SIGUSR2) exit(EXIT_SUCCESS);
	terminate = true;
}

static int loadFile(const char * const path, unsigned char *target, size_t * const len, const off_t expectedLen) {
	const int fd = open(path, O_RDONLY);
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
	   loadFile(AEM_PATH_KEY_ADR, key_adr, NULL, AEM_LEN_KEY_ADR) == 0
	&& loadFile(AEM_PATH_KEY_API, key_api, NULL, AEM_LEN_KEY_API) == 0
	&& loadFile(AEM_PATH_KEY_MNG, key_mng, NULL, AEM_LEN_KEY_MNG) == 0

	&& loadFile(AEM_PATH_TLS_CRT, tls_crt, &len_tls_crt, 0) == 0
	&& loadFile(AEM_PATH_TLS_KEY, tls_key, &len_tls_key, 0) == 0

	&& loadFile(AEM_PATH_WEB_CSS, web_css, &len_web_css, 0) == 0
	&& loadFile(AEM_PATH_WEB_HTM, web_htm, &len_web_htm, 0) == 0
	&& loadFile(AEM_PATH_WEB_JSA, web_jsa, &len_web_jsa, 0) == 0
	&& loadFile(AEM_PATH_WEB_JSM, web_jsm, &len_web_jsm, 0) == 0
	) ? 0 : -1;
}

// Drop all unneeded capabilities and privileges, but allow service port binds
static int setBindCap() {
	if (!CAP_IS_SUPPORTED(CAP_SETFCAP)) return -1;

	// Make CAP_NET_BIND_SERVICE ambient
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)                != 0) return -1;
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0) != 0) return -1;

	// Allow changing SecureBits for the next part
	const cap_value_t capPcap = CAP_SETPCAP;
	cap_t caps = cap_get_proc();
	if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &capPcap, CAP_SET) != 0 || cap_set_proc(caps) != 0) return -1;

	// Disable and lock further ambient caps
	const int ret = prctl(PR_SET_SECUREBITS, SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED | SECBIT_NOROOT | SECURE_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED);
	if (ret != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed to set SecureBits"); return -1;}

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
}

static int setSubLimits() {
	struct rlimit rlim;

	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_FSIZE, &rlim) != 0) return -1;

	rlim.rlim_cur = 10;
	rlim.rlim_max = 10;
	if (setrlimit(RLIMIT_OFILE, &rlim) != 0) return -1;

	return 0;
}

__attribute__((warn_unused_result))
static int dropRoot(void) {
	const struct passwd * const p = getpwnam("allears");

	return (
	   p != NULL

	&& chroot(AEM_CHROOT) == 0
	&& chdir("/") == 0

	&& setgroups(0, NULL) == 0
	&& setgid(p->pw_gid) == 0
	&& setuid(p->pw_uid) == 0

	&& getgid() == p->pw_gid
	&& getuid() == p->pw_uid
	) ? 0 : -1;
}

static void process_spawn(const int type) {
	int freeSlot = -1;

	for (int i = 0; i < AEM_MAXPROCESSES; i++) {
		if (pids[type][i] == 0) {
			freeSlot = i;
			break;
		}
	}

	if (freeSlot < 0) return;

	int fd[2];
	if (pipe2(fd, O_DIRECT) < 0) return;

	pid_t pid = fork(); // todo: use clone()
	if (pid < 0) return;

	if (pid == 0) { // Child process
		wipeKeys();

		if (prctl(PR_SET_PDEATHSIG, SIGUSR2, 0, 0, 0) != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed prctl()"); exit(EXIT_FAILURE);}
		if (close(sockClient) != 0 || close(sockMain) != 0 || close(fd[1]) != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed closing fds"); exit(EXIT_FAILURE);}
		if (setSubLimits() != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed setSubLimits()"); exit(EXIT_FAILURE);}
		if (dropRoot() != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed dropRoot()"); exit(EXIT_FAILURE);}
		if (setBindCap() != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed setBindCap()"); exit(EXIT_FAILURE);}

		char arg1[] = {fd[0], '\0'};
		char * const newargv[] = {arg1, NULL};
		switch(type) {
			case AEM_PROCESSTYPE_WEB: execv("usr/bin/allears-web", newargv); break; 
			case AEM_PROCESSTYPE_API: execv("usr/bin/allears-api", newargv); break; 
			case AEM_PROCESSTYPE_MTA: execv("usr/bin/allears-mta", newargv); break;
		}

		// Only runs if exec failed
		syslog(LOG_MAIL | LOG_NOTICE, "Failed to start process");
		exit(EXIT_FAILURE);
	}

	// Parent
	close(fd[0]);

	switch(type) {
		case AEM_PROCESSTYPE_API:
			if (
			   write(fd[1], key_adr, AEM_LEN_KEY_ADR) < 0
			|| write(fd[1], key_api, AEM_LEN_KEY_API) < 0

			|| write(fd[1], tls_crt, len_tls_crt) < 0
			|| write(fd[1], tls_key, len_tls_key) < 0
			) syslog(LOG_MAIL | LOG_NOTICE, "Failed to write to pipe: %s", strerror(errno));
		break;

		case AEM_PROCESSTYPE_MTA:
			if (
			   write(fd[1], key_adr, AEM_LEN_KEY_ADR) < 0

			|| write(fd[1], tls_crt, len_tls_crt) < 0
			|| write(fd[1], tls_key, len_tls_key) < 0
			) syslog(LOG_MAIL | LOG_NOTICE, "Failed to write to pipe: %s", strerror(errno));
		break;

		case AEM_PROCESSTYPE_WEB:
			if (
			   write(fd[1], tls_crt, len_tls_crt) < 0
			|| write(fd[1], tls_key, len_tls_key) < 0

			|| write(fd[1], web_css, len_web_css) < 0
			|| write(fd[1], web_htm, len_web_htm) < 0
			|| write(fd[1], web_jsa, len_web_jsa) < 0
			|| write(fd[1], web_jsm, len_web_jsm) < 0
			) syslog(LOG_MAIL | LOG_NOTICE, "Failed to write to pipe: %s", strerror(errno));
		break;
	}

	close(fd[1]);

	pids[type][freeSlot] = pid;
}

static void process_kill(const int type, const pid_t pid, const int sig) {
	syslog(LOG_MAIL | LOG_NOTICE, "Termination of process %d requested", pid);
	if (type < 0 || type > 2 || pid < 1) return;

	bool found = false;
	for (int i = 0; i < AEM_MAXPROCESSES; i++) {
		if (pids[type][i] == pid) {
			found = true;
			break;
		}
	}

	if (!found) {syslog(LOG_MAIL | LOG_NOTICE, "Process %d was not found", pid); return;}
	if (!process_verify(pid)) {syslog(LOG_MAIL | LOG_NOTICE, "Process %d not valid", pid); return;}

	kill(pid, sig);
}

void cryptSend(const int sock) {
	refreshPids();

	bzero(decrypted, AEM_LEN_MSG);

	for (int i = 0; i < 3; i++) {
		for (int j = 0; j < AEM_MAXPROCESSES; j++) {
			const int start = ((i * AEM_MAXPROCESSES) + j) * 4;
			memcpy(decrypted + start, &(pids[i][j]), 4);
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
	sockMain = socket(AF_INET, SOCK_STREAM, 0);
	if (sockMain < 0) {wipeKeys(); return EXIT_FAILURE;}

	if (initSocket(&sockMain, AEM_PORT_MANAGER) != 0) {wipeKeys(); return EXIT_FAILURE;}

	while (!terminate) {
		sockClient = accept(sockMain, NULL, NULL);
		if (sockClient < 0) break;
		setSocketTimeout(sockClient);
		respond_manager(sockClient);
		close(sockClient);
	}

	close(sockMain);
	wipeKeys();
	return EXIT_SUCCESS;
}
