#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"

#define AEM_ADDR_FLAG_SHIELD 128
// 64/32/16/8 unused
#define AEM_ADDR_FLAG_USE_GK 4
#define AEM_ADDR_FLAG_ACCINT 2
#define AEM_ADDR_FLAG_ACCEXT 1
#define AEM_ADDR_FLAGS_DEFAULT AEM_ADDR_FLAG_ACCEXT

#define AEM_ADDRESS_ARGON2_OPSLIMIT 3
#define AEM_ADDRESS_ARGON2_MEMLIMIT 67108864

#define AEM_LIMIT_MIB 0
#define AEM_LIMIT_NRM 1
#define AEM_LIMIT_SHD 2

unsigned char limits[AEM_USERLEVEL_MAX + 1][3] = {
//	 MiB, Nrm, Shd | MiB = value + 1; 1-256 MiB
	{31,  0,   5},
	{63,  3,  10},
	{127, 10, 30},
	{255, 50, 50} // Admin
};

struct aem_user {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char info; // & 3 = level; >> 2 = addresscount
	unsigned char private[AEM_LEN_PRIVATE];
	unsigned char addrHash[AEM_ADDRESSES_PER_USER][13];
	unsigned char addrFlag[AEM_ADDRESSES_PER_USER];
};

static struct aem_user *user = NULL;
static int userCount = 0;

static unsigned char accessKey_api[crypto_secretbox_KEYBYTES];
static unsigned char accessKey_mta[crypto_secretbox_KEYBYTES];

static unsigned char accountKey[crypto_secretbox_KEYBYTES];

static unsigned char salt_normal[AEM_LEN_SALT_ADDR];
static unsigned char salt_shield[AEM_LEN_SALT_ADDR];

static bool terminate = false;

static void sigTerm(const int sig) {
	if (sig == SIGUSR1) {
		terminate = true;
		syslog(LOG_MAIL | LOG_NOTICE, "Terminating after next connection");
		return;
	}

	sodium_memzero(accountKey, crypto_secretbox_KEYBYTES);

	sodium_memzero(salt_normal, AEM_LEN_SALT_ADDR);
	sodium_memzero(salt_shield, AEM_LEN_SALT_ADDR);

	free(user);

	syslog(LOG_MAIL | LOG_NOTICE, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

static int saveUser(void) {
	if (userCount <= 0) return -1;

	const size_t lenClear = sizeof(struct aem_user) * userCount;
	const size_t lenBlock = sizeof(struct aem_user) * 1024;
	const uint32_t lenPadding = lenBlock - (lenClear % lenBlock);

	const size_t lenPadded = 4 + lenClear + lenPadding;
	unsigned char * const padded = sodium_malloc(lenPadded);

	memcpy(padded, &lenPadding, 4);
	memcpy(padded + 4, (unsigned char*)user, lenClear);
	randombytes_buf_deterministic(padded + 4 + lenClear, lenPadded - 4 - lenClear, padded);

	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenPadded;
	unsigned char * const encrypted = malloc(lenEncrypted);
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, padded, lenPadded, encrypted, accountKey);
	sodium_free(padded);

	const int fd = open("Account.aem", O_WRONLY | O_TRUNC | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		free(encrypted);
		syslog(LOG_MAIL | LOG_NOTICE, "Failed to open Account.aem");
		return -1;
	}

	const ssize_t ret = write(fd, encrypted, lenEncrypted);
	free(encrypted);

	struct timespec zeroTime[2];
	zeroTime[0].tv_sec = 0;
	zeroTime[0].tv_nsec = 0;
	zeroTime[1].tv_sec = 0;
	zeroTime[1].tv_nsec = 0;
	futimens(fd, zeroTime);

	close(fd);

	return (ret == (ssize_t)lenEncrypted) ? 0 : -1;
}

static int loadUser(void) {
	if (userCount > 0) return -1;

	const int fd = open("Account.aem", O_RDONLY | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	const size_t lenBlock = sizeof(struct aem_user) * 1024;
	const off_t lenEncrypted = lseek(fd, 0, SEEK_END);
	const off_t lenDecrypted = lenEncrypted - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
	if (lenDecrypted < 1 || lenDecrypted % lenBlock != 4) {
		close(fd);
		return -1;
	}

	unsigned char encrypted[lenEncrypted];
	if (pread(fd, encrypted, lenEncrypted, 0) != lenEncrypted) {
		close(fd);
		return -1;
	}
	close(fd);

	unsigned char* decrypted = sodium_malloc(lenDecrypted);
	if (crypto_secretbox_open_easy(decrypted, encrypted + crypto_secretbox_NONCEBYTES, lenEncrypted - crypto_secretbox_NONCEBYTES, encrypted, accountKey) != 0) {
		sodium_free(decrypted);
		return -1;
	}

	uint32_t lenPadding;
	memcpy(&lenPadding, decrypted, 4);

	const size_t lenUserData = lenDecrypted - 4 - lenPadding;
	if (lenUserData % sizeof(struct aem_user) != 0) {
		sodium_free(decrypted);
		return -1;
	}

	user = malloc(lenUserData);
	memcpy(user, decrypted + 4, lenUserData);
	sodium_free(decrypted);

	userCount = lenUserData / sizeof(struct aem_user);
	return 0;
}

__attribute__((warn_unused_result))
static int addressToHash(unsigned char * const target, const unsigned char * const source, const bool shield) {
	if (target == NULL || source == NULL) return -1;

	unsigned char tmp[16];
	if (crypto_pwhash(tmp, 16, (const char * const)source, 15, shield? salt_shield : salt_normal, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) return -1;
	memcpy(target, tmp, 13);
	return 0;
}

static int userNumFromPubkey(const unsigned char * const pubkey) {
	for (int i = 0; i < userCount; i++) {
		if (memcmp(pubkey, user[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) return i;
	}

	return -1;
}

static int numAddresses(const int num, const bool shield) {
	int counter = 0;

	for (int i = 0; i < user[num].info >> 2; i++) {
		const bool isShield = (user[num].addrFlag[i] & AEM_ADDR_FLAG_SHIELD) == AEM_ADDR_FLAG_SHIELD;
		if (isShield == shield) counter++;
	}

	return counter;
}

static void api_account_browse(const int sock, const int num) {
	const int addrCount = user[num].info >> 2;
	const int maxUsers = ((user[num].info & 3) != 3) ? 0 : ((userCount > 1024) ? 1024 : userCount);

	unsigned char response[14 + (addrCount * 14) + AEM_LEN_PRIVATE + (maxUsers * 35)];

	response[0] = limits[0][0]; response[1]  = limits[0][1]; response[2]  = limits[0][2];
	response[3] = limits[1][0]; response[4]  = limits[1][1]; response[5]  = limits[1][2];
	response[6] = limits[2][0]; response[7]  = limits[2][1]; response[8]  = limits[2][2];
	response[9] = limits[3][0]; response[10] = limits[3][1]; response[11] = limits[3][2];

	response[12] = user[num].info & 3;
	response[13] = addrCount;
	int lenResponse = 14;

	for (int i = 0; i < addrCount; i++) {
		memcpy(response + lenResponse, user[num].addrHash[i], 13);
		response[lenResponse + 13] = user[num].addrFlag[i];
		lenResponse += 14;
	}

	memcpy(response + lenResponse, user[num].private, AEM_LEN_PRIVATE);
	lenResponse += AEM_LEN_PRIVATE;

	if ((user[num].info & 3) == 3) {
		const uint32_t numUsers = userCount;
		memcpy(response + lenResponse, &numUsers, 4);
		lenResponse += 4;

		for (int i = 0; i < maxUsers; i++) {
			response[lenResponse + 0] = user[i].info & 3;
			response[lenResponse + 1] = numAddresses(i, false);
			response[lenResponse + 2] = numAddresses(i, true);
			memcpy(response + lenResponse + 3, user[i].pubkey, 32);
			lenResponse += 35;
		}
	}

	send(sock, response, lenResponse, 0);
}

static void api_account_create(const int sock, const int num) {
	if ((user[num].info & 3) != 3) {
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
	user[userCount].info = 0;

	bzero(user[userCount].addrHash, AEM_ADDRESSES_PER_USER * 13);
	bzero(user[userCount].addrFlag, AEM_ADDRESSES_PER_USER);

	unsigned char empty[AEM_LEN_PRIVATE - crypto_box_SEALBYTES];
	bzero(empty, AEM_LEN_PRIVATE - crypto_box_SEALBYTES);
	crypto_box_seal(user[userCount].private, empty, AEM_LEN_PRIVATE - crypto_box_SEALBYTES, pubkey_new);

	userCount++;
	saveUser();
}

static void api_account_delete(const int sock, const int num) {
	if ((user[num].info & 3) != 3) {
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
		memmove((unsigned char*)user + s * delNum, (unsigned char*)user + s * (delNum + 1), s * (userCount - delNum - 1));
	}

	userCount--;
	saveUser();
}

static void api_account_update(const int sock, const int num) {
	if ((user[num].info & 3) != 3) {
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

	user[updateNum].info &= 252;
	user[updateNum].info |= buf[0] & 3;

	saveUser();
}

static void api_address_create(const int sock, const int num) {
	int addrCount = user[num].info >> 2;
	if (addrCount >= AEM_ADDRESSES_PER_USER) return;

	unsigned char addr32[15];
	unsigned char hash[13];

	const ssize_t len = recv(sock, hash, 13, 0);
	if (len == 6 && memcmp(hash, "SHIELD", 6) == 0) {
		randombytes_buf(addr32, 15);
		if (addressToHash(hash, addr32, true) != 0) return;

		user[num].addrFlag[addrCount] = AEM_ADDR_FLAGS_DEFAULT | AEM_ADDR_FLAG_SHIELD;
	} else if (len == 13) {
		user[num].addrFlag[addrCount] = AEM_ADDR_FLAGS_DEFAULT;
	} else {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed receiving data from API");
		return;
	}

	memcpy(user[num].addrHash[addrCount], hash, 13);
	addrCount++;
	user[num].info = (user[num].info & 3) + (addrCount << 2);

	saveUser();

	if (len == 6) { // Shield
		if (
		   send(sock, hash, 13, 0) != 13
		|| send(sock, addr32, 15, 0) != 15
		) syslog(LOG_MAIL | LOG_NOTICE, "Failed sending data to API");
	}
}

static void api_address_delete(const int sock, const int num) {
	unsigned char hash_del[13];
	if (recv(sock, hash_del, 13, 0) != 13) return;

	unsigned char addrCount = user[num].info >> 2;
	int delNum = -1;
	for (int i = 0; i < addrCount; i++) {
		if (memcmp(user[num].addrHash[i], hash_del, 13) == 0) {
			delNum = i;
			break;
		}
	}

	if (delNum < 0) return;

	if (delNum < (addrCount - 1)) {
		for (int i = delNum; i < addrCount - 1; i++) {
			memcpy(user[num].addrHash[i], user[num].addrHash[i + 1], 13);
			user[num].addrFlag[i] = user[num].addrFlag[i + 1];
		}
	}

	addrCount--;
	user[num].info = (user[num].info & 3) | (addrCount << 2);

	saveUser();
}

static void api_address_update(const int sock, const int num) {
	unsigned char buf[8192];
	const ssize_t len = recv(sock, buf, 8192, 0);
	if (len < 1 || len % 14 != 0) return;

	const int addrCount = user[num].info >> 2;

	for (int i = 0; i < (len / 14); i++) {
		for (int j = 0; j < addrCount; j++) {
			if (memcmp(user[num].addrHash[j], buf + (i * 14), 13) == 0) {
				user[num].addrFlag[j] = (buf[(i * 14) + 13] & (AEM_ADDR_FLAG_ACCEXT | AEM_ADDR_FLAG_ACCINT | AEM_ADDR_FLAG_USE_GK)) | (user[num].addrFlag[j] & AEM_ADDR_FLAG_SHIELD);
				break;
			}
		}
	}

	saveUser();
}

static void api_private_update(const int sock, const int num) {
	unsigned char buf[AEM_LEN_PRIVATE];
	if (recv(sock, buf, AEM_LEN_PRIVATE, 0) != AEM_LEN_PRIVATE) {
		syslog(LOG_MAIL | LOG_NOTICE, "Failed receiving data from API");
		return;
	}

	memcpy(user[num].private, buf, AEM_LEN_PRIVATE);

	saveUser();
}

static void api_setting_limits(const int sock, const int num) {
	if ((user[num].info & 3) != 3) {
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

static int hashToUserNum(const unsigned char * const hash) {
	for (int userNum = 0; userNum < userCount; userNum++) {
		for (int addrNum = 0; addrNum < (user[userNum].info >> 2); addrNum++) {
			if (memcmp(hash, user[userNum].addrHash[addrNum], 13) == 0) return userNum;
		}
	}

	return -1;
}

static void mta_getPubKey(const int sock, const unsigned char * const addr32, const bool isShield) {
	unsigned char hash[13];
	if (addressToHash(hash, addr32, isShield) != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Failed hashing address"); return;}

	const int userNum = hashToUserNum(hash);
	if (userNum < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Hash not found"); return;}

	send(sock, user[userNum].pubkey, crypto_box_PUBLICKEYBYTES, 0);
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

		const size_t encLen = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 1 + crypto_box_PUBLICKEYBYTES;
		unsigned char enc[encLen];

		ssize_t reqLen = recv(sockClient, enc, encLen, 0);
		if (reqLen < 1) {
			syslog(LOG_MAIL | LOG_NOTICE, "Invalid connection");
			close(sockClient);
			continue;
		}
		reqLen -= (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES);

		unsigned char req[reqLen];
		if (reqLen == 1 + crypto_box_PUBLICKEYBYTES && crypto_secretbox_open_easy(req, enc + crypto_secretbox_NONCEBYTES, 1 + crypto_box_PUBLICKEYBYTES + crypto_secretbox_MACBYTES, enc, accessKey_api) == 0) {
			const int num = userNumFromPubkey(req + 1);
			if (num < 0) {close(sockClient); continue;}

			switch (req[0]) {
				case AEM_API_ACCOUNT_BROWSE: api_account_browse(sockClient, num); break;
				case AEM_API_ACCOUNT_CREATE: api_account_create(sockClient, num); break;
				case AEM_API_ACCOUNT_DELETE: api_account_delete(sockClient, num); break;
				case AEM_API_ACCOUNT_UPDATE: api_account_update(sockClient, num); break;

				case AEM_API_ADDRESS_CREATE: api_address_create(sockClient, num); break;
				case AEM_API_ADDRESS_DELETE: api_address_delete(sockClient, num); break;
				case AEM_API_ADDRESS_UPDATE: api_address_update(sockClient, num); break;

				case AEM_API_PRIVATE_UPDATE: api_private_update(sockClient, num); break;
				case AEM_API_SETTING_LIMITS: api_setting_limits(sockClient, num); break;

				//default: // Invalid
			}

			close(sockClient);
			continue;
		}

		if (reqLen == 16 && crypto_secretbox_open_easy(req, enc + crypto_secretbox_NONCEBYTES, 16 + crypto_secretbox_MACBYTES, enc, accessKey_mta) == 0) {
			switch(req[0]) {
				case AEM_MTA_GETPUBKEY_NORMAL: mta_getPubKey(sockClient, req + 1, false); break;
				case AEM_MTA_GETPUBKEY_SHIELD: mta_getPubKey(sockClient, req + 1, true);  break;
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
	   read(fd, accountKey, AEM_LEN_KEY_ACC) == AEM_LEN_KEY_ACC
	&& read(fd, salt_normal, AEM_LEN_SALT_ADDR) == AEM_LEN_SALT_ADDR
	&& read(fd, salt_shield, AEM_LEN_SALT_ADDR) == AEM_LEN_SALT_ADDR
	&& read(fd, accessKey_api, AEM_LEN_ACCESSKEY) == AEM_LEN_ACCESSKEY
	&& read(fd, accessKey_mta, AEM_LEN_ACCESSKEY) == AEM_LEN_ACCESSKEY
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
	if (getuid()     == 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Must not be started as root"); return EXIT_FAILURE;}
	if (setSignals() != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed setting up signal handling"); return EXIT_FAILURE;}
	if (sodium_init() < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed initializing libsodium"); return EXIT_FAILURE;}

	if (pipeLoad(argv[0][0]) < 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed loading data"); return EXIT_FAILURE;}
	close(argv[0][0]);

	if (loadUser() != 0) {syslog(LOG_MAIL | LOG_NOTICE, "Terminating: Failed loading Account.aem"); return EXIT_FAILURE;}

	syslog(LOG_MAIL | LOG_NOTICE, "Ready");

	takeConnections();
	free(user);

	syslog(LOG_MAIL | LOG_NOTICE, "Terminating");
	return EXIT_SUCCESS;
}
