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

#include "Addr32.h"

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

static int saveUser(void) {
	if (userCount <= 0) return -1;

	const size_t len = userCount * sizeof(struct aem_user);
	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + len;
	unsigned char * const encrypted = malloc(lenEncrypted);
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, (unsigned char*)user, len, encrypted, accountKey);

	const int fd = open(AEM_PATH_USER, O_WRONLY | O_TRUNC);
	if (fd < 0) {free(encrypted); return -1;}
	const ssize_t ret = write(fd, encrypted, lenEncrypted);
	close(fd);
	free(encrypted);

	return (ret == (ssize_t)lenEncrypted) ? 0 : -1;
}

static int saveAddr(void) {
	if (addrCount <= 0) return -1;

	const size_t len = addrCount * sizeof(struct aem_addr);
	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + len;
	unsigned char * const encrypted = malloc(lenEncrypted);
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, (unsigned char*)addr, len, encrypted, accountKey);

	const int fd = open(AEM_PATH_ADDR, O_WRONLY | O_TRUNC);
	if (fd < 0) {free(encrypted); return -1;}
	const ssize_t ret = write(fd, encrypted, lenEncrypted);
	close(fd);
	free(encrypted);

	return (ret == (ssize_t)lenEncrypted) ? 0 : -1;
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

// Return a random, unused ID
static uint16_t newUserId(void) {
	uint16_t newId;
	randombytes_buf(&newId, 2);

	for (int i = 0; i < userCount; i++) {
		if (user[i].userId == newId) {
			newId++;
			i = 0;
			continue;
		}
	}

	return newId;
}

__attribute__((warn_unused_result))
static int addressToHash(const unsigned char * const source, unsigned char * const target) {
	if (addr == NULL || target == NULL) return -1;

	unsigned char tmp[16];
	return crypto_pwhash(tmp, 16, (const char * const)source, 15, addressKey, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13);
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

static void api_account_browse(const int sock, const int num) {
	unsigned char response[13 + AEM_LEN_PRIVATE];
	response[0] = limits[0][0]; response[1]  = limits[0][1]; response[2]  = limits[0][2];
	response[3] = limits[1][0]; response[4]  = limits[1][1]; response[5]  = limits[1][2];
	response[6] = limits[2][0]; response[7]  = limits[2][1]; response[8]  = limits[2][2];
	response[9] = limits[3][0]; response[10] = limits[3][1]; response[11] = limits[3][2];

	response[12] = user[num].level;
	memcpy(response + 13, user[num].private, AEM_LEN_PRIVATE);

	send(sock, response, 13 + AEM_LEN_PRIVATE, 0);

	if (user[num].level != AEM_USERLEVEL_MAX) return;

	// Admin Data
	unsigned char adminData[35 * 1024];
	bzero(adminData, 35 * 1024);

	const int maxUsers = (userCount <= 1024) ? userCount : 1024;
	for (int i = 0; i < maxUsers; i++) {
		adminData[i * 35 + 0] = user[i].level;
		adminData[i * 35 + 1] = user[i].addrNormal;
		adminData[i * 35 + 2] = user[i].addrShield;
		memcpy(adminData + i * 35 + 3, user[i].pubkey, 32);
	}

	send(sock, adminData, 35 * 1024, 0);
}

static void api_account_create(const int sock, const int num) {
	if (user[num].level != AEM_USERLEVEL_MAX) {
		const unsigned char violation = AEM_ACCOUNT_RESPONSE_VIOLATION;
		send(sock, &violation, 1, 0);
		return;
	}

	const unsigned char ok = AEM_ACCOUNT_RESPONSE_OK;
	if (send(sock, &ok, 1, 0) != 1) return;

	unsigned char pubkey_new[crypto_box_PUBLICKEYBYTES];
	if (recv(sock, pubkey_new, crypto_box_PUBLICKEYBYTES, 0) != crypto_box_PUBLICKEYBYTES) return;

	struct aem_user *user2 = realloc(user, (userCount + 1) * sizeof(struct aem_user));
	if (user2 == NULL) return;
	user = user2;

	memcpy(user[userCount].pubkey, pubkey_new, crypto_box_PUBLICKEYBYTES);
	user[userCount].userId = newUserId();
	user[userCount].level = AEM_USERLEVEL_MIN;
	user[userCount].addrNormal = 0;
	user[userCount].addrShield = 0;

	unsigned char empty[AEM_LEN_PRIVATE - crypto_box_SEALBYTES];
	bzero(empty, AEM_LEN_PRIVATE - crypto_box_SEALBYTES);
	crypto_box_seal(user[userCount].private, empty, AEM_LEN_PRIVATE - crypto_box_SEALBYTES, pubkey_new);

	userCount++;
	saveUser();
}

static void api_account_delete(const int sock, const int num) {
	if (user[num].level != AEM_USERLEVEL_MAX) {
		const unsigned char violation = AEM_ACCOUNT_RESPONSE_VIOLATION;
		send(sock, &violation, 1, 0);
		return;
	}

	const unsigned char ok = AEM_ACCOUNT_RESPONSE_OK;
	if (send(sock, &ok, 1, 0) != 1) return;

	unsigned char pubkey_del[crypto_box_PUBLICKEYBYTES];
	if (recv(sock, pubkey_del, crypto_box_PUBLICKEYBYTES, 0) != crypto_box_PUBLICKEYBYTES) return;

	const int delNum = userNumFromPubkey(pubkey_del);
	if (delNum < 0) return;

	if (delNum < (userCount - 1)) {
		const size_t s = sizeof(struct aem_user);
		memmove(user + s * num, user + s * (num + 1), s * (userCount - delNum - 1));
	}

	userCount--;
	saveUser();
}

static void api_account_update(const int sock, const int num) {
	if (user[num].level != AEM_USERLEVEL_MAX) {
		const unsigned char violation = AEM_ACCOUNT_RESPONSE_VIOLATION;
		send(sock, &violation, 1, 0);
		return;
	}

	const unsigned char ok = AEM_ACCOUNT_RESPONSE_OK;
	if (send(sock, &ok, 1, 0) != 1) return;

	unsigned char buf[crypto_box_PUBLICKEYBYTES + 1];
	if (recv(sock, buf, crypto_box_PUBLICKEYBYTES + 1, 0) != crypto_box_PUBLICKEYBYTES + 1) return;

	if (buf[0] > AEM_USERLEVEL_MAX) return;

	const int updateNum = userNumFromPubkey(buf + 1);
	if (updateNum < 0) return;

	user[updateNum].level = buf[0];

	saveUser();
}

static void api_address_create(const int sock, const int num) {
	char buf[AEM_MAXLEN_ADDRESS + 1];
	const ssize_t bytes = recv(sock, buf, AEM_MAXLEN_ADDRESS + 1, 0);

	if (bytes < 1 || bytes > AEM_MAXLEN_ADDRESS) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed receiving data from API");
		return;
	}

	unsigned char bin[15];
	if (bytes == 6 && memcmp(buf, "SHIELD", 6) == 0) {
		randombytes_buf(bin, 15);
		bin[0] &= 7; // Clear first five bits (all but 4,2,1)
	} else {
		addr32_store(bin, buf, bytes);
	}

	unsigned char hash[13];
	if (addressToHash(bin, hash) != 0) return;

	// Save address
	struct aem_addr *addr2 = realloc(addr, (addrCount + 1) * sizeof(struct aem_addr));
	if (addr2 == NULL) return;
	addr = addr2;

	memcpy(addr[addrCount].hash, hash, 13);
	addr[addrCount].userId = user[num].userId;
	addr[addrCount].flags = 0;

	addrCount++;

	send(sock, hash, 13, 0);

	saveAddr();
}

static void api_private_update(const int sock, const int num) {
	unsigned char buf[AEM_LEN_PRIVATE];
	if (recv(sock, buf, AEM_LEN_PRIVATE, 0) != AEM_LEN_PRIVATE) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed receiving data from API");
		return;
	}

	memcpy(user[num].private, buf, AEM_LEN_PRIVATE);
}

static void api_setting_limits(const int sock, const int num) {
	if (user[num].level != AEM_USERLEVEL_MAX) {
		const unsigned char violation = AEM_ACCOUNT_RESPONSE_VIOLATION;
		send(sock, &violation, 1, 0);
		return;
	}

	const unsigned char ok = AEM_ACCOUNT_RESPONSE_OK;
	if (send(sock, &ok, 1, 0) != 1) return;

	unsigned char buf[12];
	if (recv(sock, buf, 12, 0) != 12) return;

	memcpy(limits, buf, 12);

//	saveSettings(); // TODO
}

static int takeConnections(void) {
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
			const int num = userNumFromPubkey(req + 1);
			if (num < 0) {close(sockClient); continue;}

			switch (req[0]) {
				case AEM_API_ACCOUNT_BROWSE: api_account_browse(sockClient, num); break;
				case AEM_API_ACCOUNT_CREATE: api_account_create(sockClient, num); break;
				case AEM_API_ACCOUNT_DELETE: api_account_delete(sockClient, num); break;
				case AEM_API_ACCOUNT_UPDATE: api_account_update(sockClient, num); break;

				case AEM_API_ADDRESS_CREATE: api_address_create(sockClient, num); break;

				case AEM_API_PRIVATE_UPDATE: api_private_update(sockClient, num); break;

				case AEM_API_SETTING_LIMITS: api_setting_limits(sockClient, num); break;

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
