#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/UnixSocketClient.h"
#include "../Data/address.h"
#include "../Global.h"

#define AEM_ADDR_FLAG_SHIELD 128
// 64/32/16/8/4 unused
#define AEM_ADDR_FLAG_ACCINT 2
#define AEM_ADDR_FLAG_ACCEXT 1
#define AEM_ADDR_FLAGS_DEFAULT AEM_ADDR_FLAG_ACCEXT

#define AEM_LIMIT_MIB 0
#define AEM_LIMIT_NRM 1
#define AEM_LIMIT_SHD 2

static unsigned char limits[AEM_USERLEVEL_MAX + 1][3] = {
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

static unsigned char accountKey[AEM_LEN_KEY_ACC];
static unsigned char saltShield[AEM_LEN_SLT_SHD];

static int saveUser(void) {
	if (userCount <= 0) return -1;

	const size_t lenClear = sizeof(struct aem_user) * userCount;
	const size_t lenBlock = sizeof(struct aem_user) * 1024;
	const uint32_t lenPadding = lenBlock - (lenClear % lenBlock);

	const size_t lenPadded = 4 + lenClear + lenPadding;
	unsigned char * const padded = sodium_malloc(lenPadded);
	if (padded == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}

	memcpy(padded, &lenPadding, 4);
	memcpy(padded + 4, (unsigned char*)user, lenClear);
	randombytes_buf_deterministic(padded + 4 + lenClear, lenPadded - 4 - lenClear, padded);

	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenPadded;
	unsigned char * const encrypted = malloc(lenEncrypted);
	if (encrypted == NULL) {sodium_free(padded); syslog(LOG_ERR, "Failed allocation"); return -1;}
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
	if (fd < 0) return -1;

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
	if (decrypted == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}

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
	if (user == NULL) {sodium_free(decrypted); syslog(LOG_ERR, "Failed allocation"); return -1;}

	memcpy(user, decrypted + 4, lenUserData);
	sodium_free(decrypted);

	userCount = lenUserData / sizeof(struct aem_user);
	return 0;
}

int ioSetup(const unsigned char * const newAccountKey, const unsigned char * const newSaltShield) {
	memcpy(accountKey, newAccountKey, AEM_LEN_KEY_ACC);
	memcpy(saltShield, newSaltShield, AEM_LEN_SLT_SHD);
	return loadUser();
}

void ioFree(void) {
	sodium_memzero(accountKey, AEM_LEN_KEY_ACC);
	sodium_memzero(saltShield, AEM_LEN_SLT_SHD);
	free(user);
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
	if (addr32 == NULL) return 0;

	if (shield) {
		uint64_t hash;
		crypto_shorthash((unsigned char*)&hash, addr32, 10, saltShield);
		return hash;
	}

	uint64_t halves[2];
	if (crypto_pwhash((unsigned char*)halves, 16, (const char*)addr32, 10, AEM_SLT_NRM, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) {
		syslog(LOG_ERR, "Failed hashing address");
		return 0;
	}
	return halves[0] ^ halves[1];
}

int userNumFromPubkey(const unsigned char * const pubkey) {
	for (int i = 0; i < userCount; i++) {
		if (memcmp(pubkey, user[i].pubkey, crypto_box_PUBLICKEYBYTES) == 0) return i;
	}

	return -1;
}

static int numAddresses(const int num, const bool shield) {
	int counter = 0;

	for (int i = 0; i < user[num].info >> 3; i++) {
		const bool isShield = (user[num].addrFlag[i] & AEM_ADDR_FLAG_SHIELD) > 0;
		if (isShield == shield) counter++;
	}

	return counter;
}

void api_internal_uinfo(const int sock, const int num) {
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

void api_internal_pubks(const int sock, const int num) {
	if ((user[num].info & 3) != 3) return;

	if (send(sock, &userCount, sizeof(int), 0) != sizeof(int)) return;

	unsigned char * const response = malloc(userCount * crypto_box_PUBLICKEYBYTES);
	if (response == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}
	for (int i = 0; i < userCount; i++) {
		memcpy(response + (i * crypto_box_PUBLICKEYBYTES), user[i].pubkey, crypto_box_PUBLICKEYBYTES);
	}

	send(sock, response, userCount * crypto_box_PUBLICKEYBYTES, 0);
	free(response);
}

void api_account_browse(const int sock, const int num) {
	if ((user[num].info & 3) != 3) return;

	if (send(sock, &userCount, sizeof(int), 0) != sizeof(int)) return;

	unsigned char * const response = malloc(userCount * 35);
	if (response == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

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
	free(response);
}

void api_account_create(const int sock, const int num) {
	if ((user[num].info & 3) != 3) return;

	unsigned char pubkey_new[crypto_box_PUBLICKEYBYTES];
	if (recv(sock, pubkey_new, crypto_box_PUBLICKEYBYTES, 0) != crypto_box_PUBLICKEYBYTES) return;

	// Forbidden pubkeys
	unsigned char pubkey_inv[crypto_box_PUBLICKEYBYTES];
	memset(pubkey_inv, 0x00, crypto_box_PUBLICKEYBYTES); if (memcmp(pubkey_new, pubkey_inv, crypto_box_PUBLICKEYBYTES) == 0) return;
	memset(pubkey_inv, 0xFF, crypto_box_PUBLICKEYBYTES); if (memcmp(pubkey_new, pubkey_inv, crypto_box_PUBLICKEYBYTES) == 0) return;

	if (userNumFromPubkey(pubkey_new) >= 0) {
		send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_EXIST}, 1, 0);
		return;
	}

	struct aem_user *user2 = realloc(user, (userCount + 1) * sizeof(struct aem_user));
	if (user2 == NULL) {syslog(LOG_ERR, "Failed allocaction"); return;}
	user = user2;

	bzero(&(user[userCount]), sizeof(struct aem_user));
	memcpy(user[userCount].pubkey, pubkey_new, crypto_box_PUBLICKEYBYTES);

	userCount++;
	send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
	saveUser();
}

void api_account_delete(const int sock, const int num) {
	unsigned char pubkey_del[crypto_box_PUBLICKEYBYTES];
	if (recv(sock, pubkey_del, crypto_box_PUBLICKEYBYTES, 0) != crypto_box_PUBLICKEYBYTES) return;

	const int delNum = userNumFromPubkey(pubkey_del);
	if (delNum < 0) return;

	// Users can only delete themselves
	if ((user[num].info & 3) != 3 && delNum != num) {
		send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_VIOLATION}, 1, 0);
		return;
	}

	if (delNum < (userCount - 1)) {
		const size_t s = sizeof(struct aem_user);
		memmove((unsigned char*)user + s * delNum, (unsigned char*)user + s * (delNum + 1), s * (userCount - delNum - 1));
	}

	userCount--;
	saveUser();

	send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
}

void api_account_update(const int sock, const int num) {
	unsigned char buf[crypto_box_PUBLICKEYBYTES + 1];
	if (recv(sock, buf, crypto_box_PUBLICKEYBYTES + 1, 0) != crypto_box_PUBLICKEYBYTES + 1) return;

	if (buf[0] > AEM_USERLEVEL_MAX) return;

	const int updateNum = userNumFromPubkey(buf + 1);
	if (updateNum < 0) return;

	// If not admin && (updating another user || new-level >= current-level)
	if ((user[num].info & 3) != 3 && (updateNum != num || buf[0] >= (user[num].info & 3))) {
		const unsigned char violation = AEM_INTERNAL_RESPONSE_VIOLATION;
		send(sock, &violation, 1, 0);
		return;
	}

	if ((user[updateNum].info & 3) == (buf[0] & 3)) {
		// Trying to set level to what it already is
		return;
	}

	user[updateNum].info = (user[updateNum].info & 252) | (buf[0] & 3);
	saveUser();

	send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
}

void api_address_create(const int sock, const int num) {
	int addrCount = user[num].info >> 3;
	if (addrCount >= AEM_ADDRESSES_PER_USER) {
		send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_LIMIT}, 1, 0);
		return;
	}

	send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);

	uint64_t hash;
	const ssize_t len = recv(sock, &hash, 8, 0);
	const bool isShield = (len == 6 && memcmp(&hash, "SHIELD", 6) == 0);

	unsigned char addr32[10];
	if (isShield) {
		randombytes_buf(addr32, 10);
		hash = (memcmp(addr32 + 2, AEM_ADDR32_ADMIN, 8) == 0) ? 0 : addressToHash(addr32, true); // Forbid addresses ending with 'administrator'

		if (hash == 0 || hash == UINT64_MAX) {
			send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_EXIST}, 1, 0);
			return;
		}
	} else if (len == 8) {
		if ((user[num].info & 3) != 3) {
			// Not admin, check if hash is forbidden
			for (unsigned int i = 0; i < AEM_HASH_ADMIN_COUNT; i++) {
				if (hash == AEM_HASH_ADMIN[i]) {
					hash = 0;
					break;
				}
			}
		}

		if (hash == 0 || hash == UINT64_MAX || hash == AEM_HASH_PUBLIC || hash == AEM_HASH_SYSTEM) {
			send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_EXIST}, 1, 0);
			return;
		}
	} else {
		syslog(LOG_ERR, "Failed receiving data from API");
		return;
	}

	if (hashToUserNum(hash, isShield, NULL) >= 0) {
		// Address in use
		send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_EXIST}, 1, 0);
		return;
	}

	user[num].addrHash[addrCount] = hash;
	user[num].addrFlag[addrCount] = isShield? (AEM_ADDR_FLAGS_DEFAULT | AEM_ADDR_FLAG_SHIELD) : AEM_ADDR_FLAGS_DEFAULT;
	addrCount++;
	user[num].info = (user[num].info & 3) + (addrCount << 3);

	saveUser();

	if (isShield) {
		unsigned char data[18];
		memcpy(data, &hash, 8);
		memcpy(data + 8, addr32, 10);

		if (send(sock, data, 18, 0) != 18) syslog(LOG_ERR, "Failed sending data to API");
	} else {
		if (send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0) != 1) syslog(LOG_ERR, "Failed sending data to API");
	}
}

void api_address_delete(const int sock, const int num) {
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

	if (delNum < 0) {
		send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_NOTEXIST}, 1, 0);
		return;
	}

	if (delNum < (addrCount - 1)) {
		for (int i = delNum; i < addrCount - 1; i++) {
			user[num].addrHash[i] = user[num].addrHash[i + 1];
			user[num].addrFlag[i] = user[num].addrFlag[i + 1];
		}
	}

	addrCount--;
	user[num].info = (user[num].info & 3) | (addrCount << 3);

	saveUser();
	send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
}

void api_address_update(const int sock, const int num) {
	unsigned char buf[8192];
	const ssize_t len = recv(sock, buf, 8192, 0);
	if (len < 1 || len % 9 != 0) return;

	int found = 0;

	const int addrCount = user[num].info >> 3;
	for (int i = 0; i < (len / 9); i++) {
		for (int j = 0; j < addrCount; j++) {
			if (*(uint64_t*)(buf + (i * 9)) == user[num].addrHash[j]) {
				user[num].addrFlag[j] = (buf[(i * 9) + 8] & (AEM_ADDR_FLAG_ACCEXT | AEM_ADDR_FLAG_ACCINT)) | (user[num].addrFlag[j] & AEM_ADDR_FLAG_SHIELD);
				found++;
				break;
			}
		}
	}

	saveUser();

	unsigned char resp = AEM_INTERNAL_RESPONSE_NOTEXIST;
	if (found == len / 9) resp = AEM_INTERNAL_RESPONSE_OK;
	else if (found > 0) resp = AEM_INTERNAL_RESPONSE_PARTIAL;

	send(sock, &resp, 1, 0);
}

void api_message_sender(const int sock, const int num) {
	if ((user[num].info & 3) != 3) return;

	if (send(sock, &userCount, sizeof(int), 0) != sizeof(int)) return;

	const size_t lenResponse = userCount * crypto_box_PUBLICKEYBYTES;
	unsigned char * const response = malloc(lenResponse);
	if (response == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

	for (int i = 0; i < userCount; i++) {
		memcpy(response + (i * crypto_box_PUBLICKEYBYTES), user[i].pubkey, crypto_box_PUBLICKEYBYTES);
	}

	send(sock, response, lenResponse, 0);
	free(response);
}

void api_private_update(const int sock, const int num) {
	unsigned char buf[AEM_LEN_PRIVATE];
	if (recv(sock, buf, AEM_LEN_PRIVATE, 0) != AEM_LEN_PRIVATE) {
		syslog(LOG_ERR, "Failed receiving data from API");
		return;
	}

	memcpy(user[num].private, buf, AEM_LEN_PRIVATE);

	saveUser();
}

void api_setting_limits(const int sock, const int num) {
	if ((user[num].info & 3) != 3) return;

	unsigned char buf[12];
	if (recv(sock, buf, 12, 0) != 12) return;

	const int stoSock = storageSocket(AEM_ACC_SETTING_LIMITS, (unsigned char[]){buf[0], buf[3], buf[6], buf[9]}, 4);
	if (stoSock < 0) return;
	if (recv(stoSock, buf, 1, 0) != 1 || *buf != AEM_INTERNAL_RESPONSE_OK) {close(stoSock); return;}
	close(stoSock);

//	saveSettings(); // TODO

	memcpy(limits, buf, 12);
	send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
}

void api_internal_level(const int sock, const int num) {
	const unsigned char level = user[num].info & 3;
	send(sock, &level, 1, 0);
}

static uint64_t getAddrHash(const int sock, bool * const isShield) {
	unsigned char buf[11];
	if (recv(sock, buf, 11, 0) != 11) return 0;

	*isShield = (buf[0] == 'S');
	if (!(*isShield) && ((memcmp(buf + 1, AEM_ADDR32_PUBLIC, 10) == 0) || memcmp(buf + 1, AEM_ADDR32_SYSTEM, 10) == 0)) return 0;

	return addressToHash(buf + 1, *isShield);
}

void api_internal_adrpk(const int sock, const int num) {
	bool isShield;
	const uint64_t hash = getAddrHash(sock, &isShield);
	if (hash == 0) return;

	unsigned char flags;
	const int userNum = hashToUserNum(hash, isShield, &flags);
	if (userNum < 0 || ((user[num].info & 3) != 3 && (flags & AEM_ADDR_FLAG_ACCINT) == 0)) {
		send(sock, (unsigned char[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 32, 0);
		return;
	}

	send(sock, user[userNum].pubkey, crypto_box_PUBLICKEYBYTES, 0);
}

void api_internal_myadr(const int sock, const int num) {
	bool isShield;
	const uint64_t hash = getAddrHash(sock, &isShield);
	if (hash == 0) return;

	const int userNum = hashToUserNum(hash, isShield, NULL);
	if (userNum == num) send(sock, (unsigned char[]){AEM_INTERNAL_RESPONSE_OK}, 1, 0);
}

void mta_getPubKey(const int sock, const unsigned char * const addr32, const bool isShield) {
	const uint64_t hash = addressToHash(addr32, isShield);
	if (hash == 0) return;

	unsigned char flags;
	const int userNum = hashToUserNum(hash, isShield, &flags);
	if (userNum < 0 || (flags & AEM_ADDR_FLAG_ACCEXT) == 0) return;

	send(sock, user[userNum].pubkey, crypto_box_PUBLICKEYBYTES, 0);
}

void mta_shieldExist(const int sock, const unsigned char * const addr32) {
	const uint64_t hash = addressToHash(addr32, true);
	if (hash > 0 && hashToUserNum(hash, true, NULL) >= 0) send(sock, (unsigned char[]){0}, 1, 0);
}
