#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"

#define AEM_ADDR_EXTMSG 0
#define AEM_ADDR_INTMSG 1
#define AEM_ADDR_USE_GK 2

#define AEM_ADDRESS_ARGON2_OPSLIMIT 3
#define AEM_ADDRESS_ARGON2_MEMLIMIT 67108864

#define AEM_PATH_ADDR "Addr.aem"
#define AEM_PATH_USER "User.aem"

#define AEM_LIMIT_MIB 0
#define AEM_LIMIT_NRM 1
#define AEM_LIMIT_SHD 2

unsigned char limits[AEM_USERLEVEL_MAX + 1][3] = {
//	 MiB, Nrm, Shd | MiB = value + 1; 1-256 MiB
	{31,  0,   5},
	{63,  5,   25},
	{127, 25,  100},
	{255, 100, 250} // Admin
};

struct aem_user {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	uint16_t userId; // Max 65,536 users
	unsigned char level;
	unsigned char addrNormal;
	unsigned char addrShield;
	unsigned char private[AEM_LEN_PRIVATE];
};

struct aem_addr {
	unsigned char hash[13];
	uint16_t userId;
	unsigned char flags;
};

static struct aem_user *user = NULL;
static struct aem_addr *addr = NULL;

static int userCount = 0;
static int addrCount = 0;

static unsigned char accessKey_api[crypto_secretbox_KEYBYTES];
static unsigned char accessKey_mta[crypto_secretbox_KEYBYTES];

static unsigned char accountKey[crypto_secretbox_KEYBYTES];
static unsigned char addressKey[crypto_pwhash_SALTBYTES];

static bool terminate = false;

static void sigTerm(int sig) {
	if (sig != SIGUSR2) {
		terminate = true;
		syslog(LOG_MAIL | LOG_NOTICE, "Terminating after next connection");
		return;
	}

	sodium_memzero(accountKey, crypto_secretbox_KEYBYTES);
	sodium_memzero(addressKey, crypto_pwhash_SALTBYTES);

	sodium_memzero(user, sizeof(struct aem_user) * userCount);
	free(user);

	if (addr != NULL) {
		sodium_memzero(addr, sizeof(struct aem_addr) * addrCount);
		free(addr);
	}

	syslog(LOG_MAIL | LOG_NOTICE, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

// === Save and load functions

static int saveUser() {
	if (userCount <= 0) return -1;

	size_t len = userCount * sizeof(struct aem_user);
	size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + len;
	unsigned char *encrypted = malloc(lenEncrypted);
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, (unsigned char*)user, len, encrypted, accountKey);

	const int fd = open(AEM_PATH_USER, O_WRONLY | O_TRUNC);
	if (fd < 0) {free(encrypted); return -1;}
	if (write(fd, encrypted, lenEncrypted) != (ssize_t)lenEncrypted) {free(encrypted); return -1;}
	free(encrypted);
	close(fd);

	return 0;
}

static int saveAddr() {
	if (addrCount <= 0) return -1;

	size_t len = addrCount * sizeof(struct aem_addr);
	size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + len;
	unsigned char *encrypted = malloc(lenEncrypted);
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, (unsigned char*)addr, len, encrypted, accountKey);

	const int fd = open(AEM_PATH_ADDR, O_WRONLY | O_TRUNC);
	if (fd < 0) {free(encrypted); return -1;}
	if (write(fd, encrypted, lenEncrypted) != (ssize_t)lenEncrypted) {free(encrypted); return -1;}
	free(encrypted);
	close(fd);

	return 0;
}

static int loadAddr(void) {
	if (addrCount >= 0) return -1;

	const int fd = open(AEM_PATH_ADDR, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	const off_t lenEncrypted = lseek(fd, 0, SEEK_END);
	if (lenEncrypted < 0) {
		close(fd);
		return -1;
	}

	const size_t lenDecrypted = lenEncrypted - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
	if (lenDecrypted < sizeof(struct aem_addr) || lenDecrypted % sizeof(struct aem_addr) != 0) {
		close(fd);
		return -1;
	}

	unsigned char encrypted[lenEncrypted];
	if (pread(fd, encrypted, lenEncrypted, 0) != lenEncrypted) {
		close(fd);
		return -1;
	}
	close(fd);

	addr = malloc(lenDecrypted);

	if (crypto_secretbox_open_easy((unsigned char*)addr, encrypted + crypto_secretbox_NONCEBYTES, lenEncrypted - crypto_secretbox_NONCEBYTES, encrypted, accountKey) != 0) {
		free(addr);
		return -1;
	}

	addrCount = lenDecrypted / sizeof(struct aem_addr);
	return 0;
}

static int loadUser(void) {
	if (userCount != 0) return -1;

	const int fd = open(AEM_PATH_USER, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	const off_t lenEncrypted = lseek(fd, 0, SEEK_END);
	if (lenEncrypted < 0) {
		close(fd);
		return -1;
	}

	const size_t lenDecrypted = lenEncrypted - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
	if (lenDecrypted < sizeof(struct aem_user) || lenDecrypted % sizeof(struct aem_user) != 0) {
		close(fd);
		return -1;
	}

	unsigned char encrypted[lenEncrypted];
	if (pread(fd, encrypted, lenEncrypted, 0) != lenEncrypted) {
		close(fd);
		return -1;
	}
	close(fd);

	user = malloc(lenDecrypted);

	if (crypto_secretbox_open_easy((unsigned char*)user, encrypted + crypto_secretbox_NONCEBYTES, lenEncrypted - crypto_secretbox_NONCEBYTES, encrypted, accountKey) != 0) {
		free(user);
		return -1;
	}

	userCount = lenDecrypted / sizeof(struct aem_user);
	return 0;
}

// === Address functions

/*
static int genShieldAddress(const uint64_t upk64) {
//	randombytes_buf(

	return 0;
}
*/

// === Other functions

__attribute__((warn_unused_result))
static int addressToHash(const unsigned char * const addr, unsigned char * const target) {
	if (addr == NULL || target == NULL) return -1;

	unsigned char tmp[16];
	return crypto_pwhash(tmp, 16, (const char * const)addr, 15, addressKey, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13);
	memcpy(target, tmp, 13);
}

static int getUserNum(const uint16_t id) {
	for (int i = 0; i < userCount; i++) {
		if (user[i].userId == id) return i;
	}

	return -1;
}

/*
static int addressToUpk(const unsigned char * const src, unsigned char * const upk, unsigned char * const flags) { // getPublicKeyFromAddress
	if (src == NULL || upk == NULL) return -1;

	unsigned char cmp[13];
	if (addressToHash(src, cmp) == 0) {
		for (int i = 0; i < addrCount; i++) {
			if (memcmp(cmp, addr[i].hash, 13)) {
				const int num = getUserNum(addr[i].userId);
				if (num < 0) return -1;

				memcpy(upk, user[num].pubkey, crypto_box_PUBLICKEYBYTES);
				return 0;
			}
		}
	}

	return -1;
}
*/

static int userNumFromPubkey(const unsigned char * const pubkey) {
	for (int i = 0; i < userCount; i++) {
		if (memcmp(pubkey, user[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) return i;
	}

	return -1;
}

static int api_account_browse(const int sock, const unsigned char * const pubkey) {
	const int num = userNumFromPubkey(pubkey);
	if (num < 0) return -1;

	unsigned char response[13 + AEM_LEN_PRIVATE];
	response[0] = limits[0][0]; response[1]  = limits[0][1]; response[2]  = limits[0][2];
	response[3] = limits[1][0]; response[4]  = limits[1][1]; response[5]  = limits[1][2];
	response[6] = limits[2][0]; response[7]  = limits[2][1]; response[8]  = limits[2][2];
	response[9] = limits[3][0]; response[10] = limits[3][1]; response[11] = limits[3][2];

	response[12] = user[num].level;
	memcpy(response + 13, user[num].private, AEM_LEN_PRIVATE);

	send(sock, response, 13 + AEM_LEN_PRIVATE, 0);
	return 0;
}

static int takeConnections() {
	struct sockaddr_un local;
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, "Account.sck");

	const int sockMain = socket(AF_UNIX, SOCK_STREAM, 0);
	if (bind(sockMain, (struct sockaddr*)&local, strlen(local.sun_path) + sizeof(local.sun_family)) != 0) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed binding to socket: %s", strerror(errno));
		return -1;
	}

	listen(sockMain, 50);

	while (!terminate) {
		const int sockClient = accept(sockMain, NULL, NULL);
		if (sockClient < 0) continue;

		const size_t encLen = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + crypto_box_PUBLICKEYBYTES + 1;
		unsigned char enc[encLen];

		if (recv(sockClient, enc, encLen, 0) != encLen) {
			syslog(LOG_MAIL | LOG_NOTICE, "Invalid connection");
			close(sockClient);
			continue;
		}

		unsigned char req[1 + crypto_box_PUBLICKEYBYTES];
		if (crypto_secretbox_open_easy(req, enc + crypto_secretbox_NONCEBYTES, 1 + crypto_box_PUBLICKEYBYTES + crypto_secretbox_MACBYTES, enc, accessKey_api) == 0) {
			switch (req[0]) {
				case AEM_API_ACCOUNT_BROWSE: api_account_browse(sockClient, req + 1); break;
				//default: // Invalid
			}

			close(sockClient);
			continue;
		}

		if (crypto_secretbox_open_easy(req, enc + crypto_secretbox_NONCEBYTES, 1 + crypto_box_PUBLICKEYBYTES + crypto_secretbox_MACBYTES, enc, accessKey_api) == 0) {
			switch (req[0]) {
				//case AEM_MTA_: mta_(sockClient, req + 1); break;
				//case AEM_MTA_: mta_(sockClient, req + 1); break;
				//default: // Invalid
			}

			close(sockClient);
			continue;
		}

		close(sockClient);
		syslog(LOG_MAIL | LOG_NOTICE, "Invalid request");
	}

	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoad(const int fd) {
	return (
	   read(fd, accountKey,    crypto_secretbox_KEYBYTES) == crypto_secretbox_KEYBYTES
	&& read(fd, addressKey,    crypto_pwhash_SALTBYTES)   == crypto_pwhash_SALTBYTES
	&& read(fd, accessKey_api, crypto_secretbox_KEYBYTES) == crypto_secretbox_KEYBYTES
	&& read(fd, accessKey_mta, crypto_secretbox_KEYBYTES) == crypto_secretbox_KEYBYTES
	) ? 0 : -1;
}

static int setSignals(void) {
	return (
	   signal(SIGPIPE, SIG_IGN) != SIG_ERR

	&& signal(SIGINT,  sigTerm) != SIG_ERR
	&& signal(SIGQUIT, sigTerm) != SIG_ERR
	&& signal(SIGTERM, sigTerm) != SIG_ERR
	&& signal(SIGUSR1, sigTerm) != SIG_ERR
	&& signal(SIGUSR2, sigTerm) != SIG_ERR
	) ? 0 : -1;
}

int main(int argc, char *argv[]) {
	if (argc > 1 || argv == NULL) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Invalid arguments"); return EXIT_FAILURE;}
	if (getuid()      == 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Must not be started as root"); return EXIT_FAILURE;}
	if (setSignals()  != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed setting up signal handling"); return EXIT_FAILURE;}
	if (sodium_init()  < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed initializing libsodium"); return EXIT_FAILURE;}

	if (pipeLoad(argv[0][0]) < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed loading data"); return EXIT_FAILURE;}
	close(argv[0][0]);

	if (loadUser() != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed loading User.aem"); return EXIT_FAILURE;}
//	loadAddr();

	syslog(LOG_MAIL | LOG_NOTICE, "Ready");
	takeConnections();
	syslog(LOG_MAIL | LOG_NOTICE, "Terminating");
	return EXIT_SUCCESS;
}
