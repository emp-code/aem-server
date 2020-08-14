#include <fcntl.h>
#include <locale.h> // for setlocale
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> // for mlockall
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/SetCaps.h"

#define AEM_ACCOUNT
#define AEM_LOGNAME "AEM-Acc"

#define AEM_MAXLEN_PIPEREAD 65533 // 5041 hashes max
#define AEM_MINLEN_PIPEREAD 8

#define AEM_ADDR_FLAG_SHIELD 128
// 64/32/16/8 unused
#define AEM_ADDR_FLAG_USE_GK 4
#define AEM_ADDR_FLAG_ACCINT 2
#define AEM_ADDR_FLAG_ACCEXT 1
#define AEM_ADDR_FLAGS_DEFAULT AEM_ADDR_FLAG_ACCEXT

#define AEM_LIMIT_MIB 0
#define AEM_LIMIT_NRM 1
#define AEM_LIMIT_SHD 2

unsigned char limits[AEM_USERLEVEL_MAX + 1][3] = {
//	 MiB  Nrm Shd | MiB = value + 1; 1-256 MiB
	{31,  0,  5},
	{63,  3,  10},
	{127, 10, AEM_ADDRESSES_PER_USER}, // AEM_ADDRESSES_PER_USER = max
	{255, AEM_ADDRESSES_PER_USER, AEM_ADDRESSES_PER_USER} // Admin
};

struct aem_user {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char info; // & 3 = level; & 4 = unused; >> 3 = addresscount
	unsigned char private[AEM_LEN_PRIVATE];
	uint64_t addrHash[AEM_ADDRESSES_PER_USER];
	unsigned char addrFlag[AEM_ADDRESSES_PER_USER];
};

static struct aem_user *user = NULL;
static int userCount = 0;

static unsigned char accessKey_api[crypto_secretbox_KEYBYTES];
static unsigned char accessKey_mta[crypto_secretbox_KEYBYTES];

static unsigned char accountKey[crypto_secretbox_KEYBYTES];

static unsigned char salt_normal[AEM_LEN_SALT_NORM];
static unsigned char salt_shield[AEM_LEN_SALT_SHLD];
static unsigned char salt_fake[crypto_generichash_KEYBYTES];

static uint64_t hash_system;
static uint64_t *hash_admin;
static int hash_admin_count = 0;

static bool terminate = false;

static void sigTerm(const int sig) {
	if (sig == SIGUSR1) {
		terminate = true;
		syslog(LOG_INFO, "Terminating after next connection");
		return;
	}

	sodium_memzero(accountKey, crypto_secretbox_KEYBYTES);
	sodium_memzero(salt_normal, AEM_LEN_SALT_NORM);
	sodium_memzero(salt_shield, AEM_LEN_SALT_SHLD);

	free(user);
	sodium_free(hash_admin);

	syslog(LOG_INFO, "Terminating immediately");
	exit(EXIT_SUCCESS);
}

#include "../Common/main_all.c"

static int saveUser(void) {
	if (userCount <= 0) return -1;

	const size_t lenClear = sizeof(struct aem_user) * userCount;
	const size_t lenBlock = sizeof(struct aem_user) * 1024;
	const uint32_t lenPadding = lenBlock - (lenClear % lenBlock);

	const size_t lenPadded = 4 + lenClear + lenPadding;
	unsigned char * const padded = sodium_malloc(lenPadded);
	if (padded == NULL) return -1;

	memcpy(padded, &lenPadding, 4);
	memcpy(padded + 4, (unsigned char*)user, lenClear);
	randombytes_buf_deterministic(padded + 4 + lenClear, lenPadded - 4 - lenClear, padded);

	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenPadded;
	unsigned char * const encrypted = malloc(lenEncrypted);
	if (encrypted == NULL) {sodium_free(padded); return -1;}
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, padded, lenPadded, encrypted, accountKey);
	sodium_free(padded);

	const int fd = open("Account.aem", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {
		free(encrypted);
		syslog(LOG_ERR, "Failed opening Account.aem");
		return -1;
	}

	const ssize_t ret = write(fd, encrypted, lenEncrypted);
	free(encrypted);

	close(fd);
	return (ret == (ssize_t)lenEncrypted) ? 0 : -1;
}

static int loadUser(void) {
	if (userCount > 0) return -1;

	const int fd = open("Account.aem", O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
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

	unsigned char * const decrypted = sodium_malloc(lenDecrypted);
	if (decrypted == NULL) return -1;

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
	if (user == NULL) {sodium_free(decrypted); return -1;}

	memcpy(user, decrypted + 4, lenUserData);
	sodium_free(decrypted);

	userCount = lenUserData / sizeof(struct aem_user);
	return 0;
}

static int hashToUserNum(const uint64_t hash, const bool isShield, unsigned char * const flagp) {
	for (int userNum = 0; userNum < userCount; userNum++) {
		for (int addrNum = 0; addrNum < (user[userNum].info >> 3); addrNum++) {
			if (hash == user[userNum].addrHash[addrNum]) {
				if (flagp != NULL) *flagp = user[userNum].addrFlag[addrNum];

				if (isShield) {
					return ((user[userNum].addrFlag[addrNum] & AEM_ADDR_FLAG_SHIELD) > 0) ? userNum : -1;
				} else {
					return ((user[userNum].addrFlag[addrNum] & AEM_ADDR_FLAG_SHIELD) == 0) ? userNum : -1;
				}
			}
		}
	}

	return -1;
}

__attribute__((warn_unused_result))
static uint64_t addressToHash(const unsigned char * const addr32, const bool shield) {
	if (addr32 == NULL) return -1;

	if (shield) {
		uint64_t hash;
		crypto_shorthash((unsigned char*)&hash, addr32, 10, salt_shield);
		return hash;
	}

	uint64_t halves[2];
	if (crypto_pwhash((unsigned char*)halves, 16, (const char*)addr32, 10, salt_normal, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) {
		syslog(LOG_ERR, "Failed hashing address");
		return 0;
	}

	return halves[0] ^ halves[1];
}

static int userNumFromPubkey(const unsigned char * const pubkey) {
	for (int i = 0; i < userCount; i++) {
		if (memcmp(pubkey, user[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) return i;
	}

	return -1;
}

static int numAddresses(const int num, const bool shield) {
	int counter = 0;

	for (int i = 0; i < user[num].info >> 3; i++) {
		const bool isShield = (user[num].addrFlag[i] & AEM_ADDR_FLAG_SHIELD) == AEM_ADDR_FLAG_SHIELD;
		if (isShield == shield) counter++;
	}

	return counter;
}

static void api_internal_uinfo(const int sock, const int num) {
	unsigned char response[283 + AEM_LEN_PRIVATE];
	size_t lenResponse = 4;

	response[0] = user[num].info;
	memcpy(response + 1, limits[user[num].info & 3], 3);

	for (int i = 0; i < (user[num].info >> 3); i++) {
		memcpy(response + lenResponse, &(user[num].addrHash[i]), 8);
		response[lenResponse + 8] = user[num].addrFlag[i];
		lenResponse += 9;
	}

	memcpy(response + lenResponse, user[num].private, AEM_LEN_PRIVATE);
	lenResponse += AEM_LEN_PRIVATE;

	send(sock, response, lenResponse, 0);
}

static void api_account_browse(const int sock, const int num) {
	if ((user[num].info & 3) != 3) return;

	unsigned char * const response = malloc(userCount * 35);

	response[0] = limits[0][0]; response[1]  = limits[0][1]; response[2]  = limits[0][2];
	response[3] = limits[1][0]; response[4]  = limits[1][1]; response[5]  = limits[1][2];
	response[6] = limits[2][0]; response[7]  = limits[2][1]; response[8]  = limits[2][2];
	response[9] = limits[3][0]; response[10] = limits[3][1]; response[11] = limits[3][2];

	int len = 12;

	const uint32_t u32 = userCount - 1;
	memcpy(response + len, &u32, 4);
	len += 4;

	for (int i = 0; i < userCount; i++) {
		if (i == num) continue; // Skip own user

		const int mib = 1000 +i; // TODO

/* Stores: Level=0-3, Normal=0-31, Shield=0-31, MiB=0-4095
	Bytes 0-1:
		1..2: Level
		4..64: Normal
		128..2048: Shield
		4096..32768: MiB (bits 256..2048)
	Byte 2:
		MiB (bits 1..128)
*/
		const uint16_t u16 = (user[i].info & 3) | ((numAddresses(i, false) & 31) << 2) | ((numAddresses(i, true) & 31) << 7) | ((mib & 3840) << 4);
		memcpy(response + len, &u16, 2);
		response[len + 2] = mib & 255;
		memcpy(response + len + 3, user[i].pubkey, 32);
		len += 35;
	}

	send(sock, response, len, 0);
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

	bzero(&(user[userCount]), sizeof(struct aem_user));
	memcpy(user[userCount].pubkey, pubkey_new, crypto_box_PUBLICKEYBYTES);

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
	int addrCount = user[num].info >> 3;
	if (addrCount >= AEM_ADDRESSES_PER_USER) return;

	unsigned char addr32[10];
	uint64_t hash;

	const ssize_t len = recv(sock, &hash, 8, 0);
	const bool isShield = (len == 6 && memcmp(&hash, "SHIELD", 6) == 0);

	if (isShield) {
		randombytes_buf(addr32, 10);
		if (memcmp(addr32 + 2, AEM_ADDR32_ADMIN, 8) == 0) return; // Forbid addresses ending with 'administrator'

		hash = addressToHash(addr32, true);
		if (hash == 0) return;
	} else if (len == 8) {
		if (hash == hash_system) return; // Forbid 'system' address

		if ((user[num].info & 3) != 3) {
			// Not admin, check if hash is forbidden
			for (int i = 0; i < hash_admin_count; i++) {
				if (hash == hash_admin[i]) return;
			}
		}
	} else {
		syslog(LOG_ERR, "Failed receiving data from API");
		return;
	}

	if (hashToUserNum(hash, isShield, NULL) >= 0) return; // Address in use

	user[num].addrHash[addrCount] = hash;
	addrCount++;
	user[num].info = (user[num].info & 3) + (addrCount << 3);

	saveUser();

	if (isShield) {
		unsigned char data[18];
		memcpy(data, &hash, 8);
		memcpy(data + 8, addr32, 10);

		if (send(sock, data, 18, 0) != 18) syslog(LOG_ERR, "Failed sending data to API");

		user[num].addrFlag[addrCount - 1] = AEM_ADDR_FLAGS_DEFAULT | AEM_ADDR_FLAG_SHIELD;
	} else {
		const unsigned char ok = 1;
		send(sock, &ok, 1, 0);

		user[num].addrFlag[addrCount - 1] = AEM_ADDR_FLAGS_DEFAULT;
	}
}

static void api_address_delete(const int sock, const int num) {
	uint64_t hash_del;
	if (recv(sock, &hash_del, 8, 0) != 8) return;

	unsigned char addrCount = user[num].info >> 3;
	int delNum = -1;
	for (int i = 0; i < addrCount; i++) {
		if (hash_del == user[num].addrHash[i]) {
			delNum = i;
			break;
		}
	}

	if (delNum < 0) return;

	if (delNum < (addrCount - 1)) {
		for (int i = delNum; i < addrCount - 1; i++) {
			user[num].addrHash[i] = user[num].addrHash[i + 1];
			user[num].addrFlag[i] = user[num].addrFlag[i + 1];
		}
	}

	addrCount--;
	user[num].info = (user[num].info & 3) | (addrCount << 3);

	saveUser();
}

static void api_address_lookup(const int sock) {
	unsigned char addr[11];
	if (recv(sock, addr, 11, 0) != 11) return;
	const bool isShield = addr[0] == 'S';

	const uint64_t hash = addressToHash(addr + 1, isShield);
	if (hash == 0) return;

	unsigned char addrFlags;
	const int userNum = hashToUserNum(hash, isShield, &addrFlags);
	if (userNum >= 0 && addrFlags & AEM_ADDR_FLAG_ACCINT) {
		send(sock, user[userNum].pubkey, crypto_box_PUBLICKEYBYTES, 0);
		return;
	}

	// Address doesn't exist, or blocks internal messages - respond with a deterministic fake
	unsigned char fake[crypto_box_PUBLICKEYBYTES];
	crypto_generichash(fake, sizeof(fake), (const unsigned char*)&hash, 8, salt_fake, crypto_generichash_KEYBYTES);
	send(sock, fake, crypto_box_PUBLICKEYBYTES, 0);
}

static void api_address_update(const int sock, const int num) {
	unsigned char buf[8192];
	const ssize_t len = recv(sock, buf, 8192, 0);
	if (len < 1 || len % 9 != 0) return;

	const int addrCount = user[num].info >> 3;

	for (int i = 0; i < (len / 9); i++) {
		for (int j = 0; j < addrCount; j++) {
			if ((uint64_t)(buf + (i * 9)) == user[num].addrHash[j]) {
				user[num].addrFlag[j] = (buf[(i * 9) + 8] & (AEM_ADDR_FLAG_ACCEXT | AEM_ADDR_FLAG_ACCINT | AEM_ADDR_FLAG_USE_GK)) | (user[num].addrFlag[j] & AEM_ADDR_FLAG_SHIELD);
				break;
			}
		}
	}

	saveUser();
}

static void api_private_update(const int sock, const int num) {
	unsigned char buf[AEM_LEN_PRIVATE];
	if (recv(sock, buf, AEM_LEN_PRIVATE, 0) != AEM_LEN_PRIVATE) {
		syslog(LOG_ERR, "Failed receiving data from API");
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

static void api_internal_level(const int sock, const int num) {
	const unsigned char level = user[num].info & 3;
	send(sock, &level, 1, 0);
}

static void mta_getPubKey(const int sock, const unsigned char * const addr32, const bool isShield) {
	const uint64_t hash = addressToHash(addr32, isShield);
	if (hash == 0) return;

	unsigned char flags;
	const int userNum = hashToUserNum(hash, isShield, &flags);
	if (userNum < 0 || (flags & AEM_ADDR_FLAG_ACCEXT) == 0) {syslog(LOG_DEBUG, "Hash not found"); return;}

	send(sock, user[userNum].pubkey, crypto_box_PUBLICKEYBYTES, 0);
}

static bool peerOk(const int sock) {
	struct ucred peer;
	unsigned int lenUc = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peer, &lenUc) == -1) return false;
	return (peer.gid == getgid() && peer.uid == getuid());
}

static int takeConnections(void) {
	umask(0077);

	struct sockaddr_un local;
	local.sun_family = AF_UNIX;
	memcpy(local.sun_path, AEM_SOCKPATH_ACCOUNT, AEM_SOCKPATH_LEN);

	const int sockMain = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (bind(sockMain, (struct sockaddr*)&local, sizeof(local.sun_family) + AEM_SOCKPATH_LEN) != 0) {
		syslog(LOG_ERR, "Failed binding to socket: %m");
		return -1;
	}

	listen(sockMain, 50);

	while (!terminate) {
		const int sockClient = accept4(sockMain, NULL, NULL, SOCK_CLOEXEC);
		if (sockClient < 0) continue;

		if (!peerOk(sockClient)) {
			syslog(LOG_WARNING, "Connection rejected from invalid user");
			close(sockClient);
			continue;
		}

		const size_t encLen = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 1 + crypto_box_PUBLICKEYBYTES;
		unsigned char enc[encLen];

		ssize_t reqLen = recv(sockClient, enc, encLen, 0);
		if (reqLen < 1) {
			syslog(LOG_WARNING, "Invalid connection");
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
				case AEM_API_ADDRESS_LOOKUP: api_address_lookup(sockClient); break;
				case AEM_API_ADDRESS_UPDATE: api_address_update(sockClient, num); break;

				case AEM_API_PRIVATE_UPDATE: api_private_update(sockClient, num); break;
				case AEM_API_SETTING_LIMITS: api_setting_limits(sockClient, num); break;

				// Internal functions
				case AEM_API_INTERNAL_EXIST: send(sockClient, "\x01", 1, 0); break; // existence verified by userNumFromPubkey()
				case AEM_API_INTERNAL_LEVEL: api_internal_level(sockClient, num); break;
				case AEM_API_INTERNAL_UINFO: api_internal_uinfo(sockClient, num); break;

				//default: // Invalid
			}

			close(sockClient);
			continue;
		} else if (reqLen == 11 && crypto_secretbox_open_easy(req, enc + crypto_secretbox_NONCEBYTES, 11 + crypto_secretbox_MACBYTES, enc, accessKey_mta) == 0) {
			switch(req[0]) {
				case AEM_MTA_GETPUBKEY_NORMAL: mta_getPubKey(sockClient, req + 1, false); break;
				case AEM_MTA_GETPUBKEY_SHIELD: mta_getPubKey(sockClient, req + 1, true);  break;
			}

			close(sockClient);
			continue;
		}

		close(sockClient);
		syslog(LOG_WARNING, "Invalid request");
	}

	return 0;
}

__attribute__((warn_unused_result))
static int pipeLoad(const int fd) {
	return (
	   read(fd, accountKey, AEM_LEN_KEY_ACC) == AEM_LEN_KEY_ACC

	&& read(fd, salt_normal, AEM_LEN_SALT_NORM) == AEM_LEN_SALT_NORM
	&& read(fd, salt_shield, AEM_LEN_SALT_SHLD) == AEM_LEN_SALT_SHLD
	&& read(fd, salt_fake,   AEM_LEN_SALT_FAKE) == AEM_LEN_SALT_FAKE

	&& read(fd, accessKey_api, AEM_LEN_ACCESSKEY) == AEM_LEN_ACCESSKEY
	&& read(fd, accessKey_mta, AEM_LEN_ACCESSKEY) == AEM_LEN_ACCESSKEY
	) ? 0 : -1;
}

#include "../Common/PipeLoad.c"

int main(int argc, char *argv[]) {
#include "../Common/MainSetup.c"

	if (
	   setCaps(CAP_IPC_LOCK) != 0
	|| mlockall(MCL_CURRENT | MCL_FUTURE) != 0
	) {syslog(LOG_ERR, "Terminating: Failed setting capabilities"); return EXIT_FAILURE;}

	unsigned char *hash_admin_u8;
	size_t hash_admin_size = 1;
	if (pipeLoad(argv[0][0]) < 0) {syslog(LOG_ERR, "Terminating: Failed loading data"); return EXIT_FAILURE;}
	if (pipeRead(argv[0][0], &hash_admin_u8, &hash_admin_size) < 0) {syslog(LOG_ERR, "Terminating: Failed loading admin hashes"); return EXIT_FAILURE;}
	close(argv[0][0]);

	if (hash_admin_size % 8 != 0) {syslog(LOG_ERR, "Terminating: Admin hashes: wrong size"); return EXIT_FAILURE;}
	hash_admin_count = hash_admin_size / 8;
	hash_admin = (uint64_t*)hash_admin_u8;

	hash_system = addressToHash(AEM_ADDR32_SYSTEM, false);
	if (hash_system == 0) {syslog(LOG_ERR, "Terminating: Failed hashing system address"); return EXIT_FAILURE;}

	if (loadUser() != 0) {syslog(LOG_ERR, "Terminating: Failed loading Account.aem"); return EXIT_FAILURE;}

	syslog(LOG_INFO, "Ready");

	takeConnections();
	free(user);
	sodium_free(hash_admin);

	syslog(LOG_INFO, "Terminating");
	return EXIT_SUCCESS;
}
