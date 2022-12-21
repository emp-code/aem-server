#include <fcntl.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/IntCom_Client.h"
#include "../Common/IntCom_Server.h"
#include "../Common/memeq.h"
#include "../Data/address.h"
#include "../Global.h"

#include "aem_user.h"

#define AEM_FAKEFLAGS_HTSIZE 2048
#define AEM_FAKEFLAGS_MAXTIME 2000000 // 23d

#define AEM_LIMIT_MIB 0
#define AEM_LIMIT_NRM 1
#define AEM_LIMIT_SHD 2

static unsigned char limits[AEM_USERLEVEL_MAX + 1][3] = {
// MiB, Nrm, Shd
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{255, AEM_ADDRESSES_PER_USER, AEM_ADDRESSES_PER_USER} // Admin
};

static struct aem_user *user = NULL;
static int userCount = 0;

static unsigned char accountKey[crypto_secretbox_KEYBYTES];
static unsigned char saltShield[crypto_shorthash_KEYBYTES];
static uint32_t fakeFlag_expire[AEM_FAKEFLAGS_HTSIZE];

static int saveSettings(void) {
	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + 12;
	unsigned char * const encrypted = malloc(lenEncrypted);
	if (encrypted == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, (unsigned char*)limits, 12, encrypted, accountKey);

	const int fd = open("Settings.aem", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {
		free(encrypted);
		syslog(LOG_ERR, "Failed opening Settings.aem");
		return -1;
	}

	const ssize_t ret = write(fd, encrypted, lenEncrypted);
	free(encrypted);

	close(fd);
	return (ret == (ssize_t)lenEncrypted) ? 0 : -1;
}

static int loadSettings(void) {
	const int fd = open("Settings.aem", O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) return -1;

	const off_t lenEncrypted = lseek(fd, 0, SEEK_END);
	const off_t lenDecrypted = lenEncrypted - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
	if (lenDecrypted != 12) {syslog(LOG_WARNING, "Failed loading Settings.aem - invalid size"); close(fd); return -1;}

	unsigned char encrypted[lenEncrypted];
	if (pread(fd, encrypted, lenEncrypted, 0) != lenEncrypted) {
		close(fd);
		syslog(LOG_WARNING, "Failed loading Settings.aem - failed read");
		return -1;
	}
	close(fd);

	if (crypto_secretbox_open_easy((unsigned char*)limits, encrypted + crypto_secretbox_NONCEBYTES, lenEncrypted - crypto_secretbox_NONCEBYTES, encrypted, accountKey) != 0) return -1;
	return 0;
}

static int saveUser(void) {
	if (userCount < 1) return -1;
	const size_t lenClear = sizeof(struct aem_user) * userCount;

	const size_t lenEncrypted = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + lenClear;
	unsigned char * const encrypted = malloc(lenEncrypted);
	if (encrypted == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, (unsigned char*)user, lenClear, encrypted, accountKey);

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
	if (userCount > 0) {syslog(LOG_ERR, "Account data already loaded"); return -1;}

	const int fd = open("Account.aem", O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "Failed opening Account.aem: %m"); return -1;}

	const off_t lenEncrypted = lseek(fd, 0, SEEK_END);
	const off_t lenDecrypted = lenEncrypted - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
	if (lenDecrypted < 1 || lenDecrypted % sizeof(struct aem_user) != 0) {
		close(fd);
		syslog(LOG_ERR, "Invalid size for Account.aem");
		return -1;
	}

	unsigned char encrypted[lenEncrypted];
	if (pread(fd, encrypted, lenEncrypted, 0) != lenEncrypted) {
		close(fd);
		syslog(LOG_ERR, "Failed reading Account.aem");
		return -1;
	}
	close(fd);

	user = malloc(lenDecrypted);
	if (user == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}

	if (crypto_secretbox_open_easy((unsigned char*)user, encrypted + crypto_secretbox_NONCEBYTES, lenEncrypted - crypto_secretbox_NONCEBYTES, encrypted, accountKey) != 0) {
		free(user);
		syslog(LOG_ERR, "Failed decrypting Account.aem");
		return -1;
	}

	userCount = lenDecrypted / sizeof(struct aem_user);
	return 0;
}

static int updateStorageLevels(void) {
	const size_t lenData = userCount * (crypto_box_PUBLICKEYBYTES + 1);
	unsigned char * const data = malloc(lenData);
	for (int i = 0; i < userCount; i++) {
		data[i * (crypto_box_PUBLICKEYBYTES + 1)] = user[i].info & AEM_USERLEVEL_MAX;
		memcpy(data + (i * (crypto_box_PUBLICKEYBYTES + 1)) + 1, user[i].upk, crypto_box_PUBLICKEYBYTES);
	}

	const int32_t ret = intcom(AEM_INTCOM_TYPE_STORAGE, AEM_ACC_STORAGE_LEVELS, data, lenData, NULL, 0);
	free(data);

	if (ret != AEM_INTCOM_RESPONSE_OK) {
		syslog(LOG_ERR, "updateStorageLevels: intcom failed");
		return -1;
	}

	return 0;
}

int ioSetup(const unsigned char baseKey[crypto_kdf_KEYBYTES]) {
	crypto_kdf_derive_from_key(accountKey, crypto_secretbox_KEYBYTES, 1, "AEM_Acc1", baseKey);
	crypto_kdf_derive_from_key(saltShield, crypto_shorthash_KEYBYTES, 1, "AEM_Shd1", baseKey);

	if (loadUser() != 0) return -1;
	loadSettings(); // Ignore errors
	bzero((unsigned char*)fakeFlag_expire, 4 * AEM_FAKEFLAGS_HTSIZE);

	if (intcom(AEM_INTCOM_TYPE_STORAGE, AEM_ACC_STORAGE_LIMITS, (unsigned char[4]){limits[0][0], limits[1][0], limits[2][0], limits[3][0]}, 4, NULL, 0) != AEM_INTCOM_RESPONSE_OK) {
		syslog(LOG_ERR, "ioSetup: intcom failed");
		return -1;
	}

	return updateStorageLevels();
}

void ioFree(void) {
	sodium_memzero(accountKey, crypto_secretbox_KEYBYTES);
	sodium_memzero(saltShield, crypto_shorthash_KEYBYTES);
	free(user);
}

static int hashToUserNum(const uint64_t hash, const bool isShield, unsigned char * const flagp) {
	for (int userNum = 0; userNum < userCount; userNum++) {
		for (int addrNum = 0; addrNum < (user[userNum].info >> 3); addrNum++) {
			if (hash == user[userNum].addrHash[addrNum] && (user[userNum].addrFlag[addrNum] & AEM_ADDR_FLAG_SHIELD) == (isShield? AEM_ADDR_FLAG_SHIELD : 0)) {
				if (flagp != NULL) *flagp = user[userNum].addrFlag[addrNum];
				return userNum;
			}
		}
	}

	return -1;
}

__attribute__((warn_unused_result))
static uint64_t addressToHash(const unsigned char * const addr32, const bool shield) {
	if (addr32 == NULL) return 0;

	if (shield) {
		if (memeq(addr32 + 2, AEM_ADDR32_ADMIN, 8)) return 0; // Forbid addresses ending with 'administrator'
		uint64_t hash;
		crypto_shorthash((unsigned char*)&hash, addr32, 10, saltShield);
		return hash;
	} else if (memeq(addr32, AEM_ADDR32_PUBLIC, 10) || memeq(addr32, AEM_ADDR32_SYSTEM, 10)) return 0; // Forbid 'public' and 'system'

	uint64_t halves[2];
	if (crypto_pwhash((unsigned char*)halves, 16, (const char*)addr32, 10, AEM_SLT_NRM, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) {
		syslog(LOG_ERR, "Failed hashing address");
		return 0;
	}
	return halves[0] ^ halves[1];
}

int userNumFromUpk(const unsigned char * const upk) {
	for (int i = 0; i < userCount; i++) {
		if (memeq(upk, user[i].upk, crypto_box_PUBLICKEYBYTES)) return i;
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

int32_t api_account_browse(const int num, unsigned char **res) {
	if ((user[num].info & 3) != 3) return AEM_INTCOM_RESPONSE_PERM;
	if (userCount <= 1 || res == NULL) return AEM_INTCOM_RESPONSE_ERR;

	const uint32_t lenRes = 16 + ((userCount - 1) * 35); // Exclude own user
	*res = malloc(lenRes);
	if (*res == NULL) {syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}

	memcpy(*res, (unsigned char*)limits, 12);
	const uint32_t u32 = userCount - 1;
	memcpy(*res + 12, &u32, 4);

	unsigned char *storage = NULL;
	const int32_t lenStorage = intcom(AEM_INTCOM_TYPE_STORAGE, AEM_ACC_STORAGE_AMOUNT, NULL, 0, &storage, 0);

	if ((size_t)lenStorage != userCount * (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t))) {
		syslog(LOG_WARNING, "User storage data out of sync");
		free(storage);
		storage = NULL;
	}

	int skip = 0;
	for (int i = 0; i < userCount; i++) {
		if (i == num) {skip = 1; continue;} // Skip own user

		uint32_t kib64;
		if (storage != NULL && lenStorage > 0 && memeq(user[i].upk, storage + (i * (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t))) + sizeof(uint32_t), crypto_box_PUBLICKEYBYTES)) {
			uint32_t storageBytes;
			memcpy((unsigned char*)&storageBytes, storage + (i * (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t))), sizeof(uint32_t));
			kib64 = round((double)storageBytes / 65536);
		} else kib64 = UINT32_MAX;

/* Stores: Level=0-3, Normal=0-31, Shield=0-31, kib64=0-4095
	Bytes 0-1:
		1..2: Level
		4..64: Normal
		128..2048: Shield
		4096..32768: Storage (bits 256..2048)
	Byte 2:
		Storage (bits 1..128)
*/
		const uint16_t u16 = (user[i].info & 3) | ((numAddresses(i, false) & 31) << 2) | ((numAddresses(i, true) & 31) << 7) | ((kib64 & 3840) << 4);
		memcpy(*res + 16 + ((i - skip) * 35), &u16, 2);
		(*res)[18 + ((i - skip) * 35)] = kib64 & 255;
		memcpy(*res + 19 + ((i - skip) * 35), user[i].upk, 32);
	}

	if (storage != NULL) free(storage);
	return lenRes;
}

int32_t api_account_create(const int num, const unsigned char * const msg, const size_t lenMsg) {
	if ((user[num].info & 3) != 3) return AEM_INTCOM_RESPONSE_PERM;
	if (msg == NULL || lenMsg != crypto_box_PUBLICKEYBYTES) return AEM_INTCOM_RESPONSE_ERR;

	// Forbidden UPKs
	unsigned char upk_inv[crypto_box_PUBLICKEYBYTES];
	memset(upk_inv, 0x00, crypto_box_PUBLICKEYBYTES); if (memeq(msg, upk_inv, crypto_box_PUBLICKEYBYTES)) return AEM_INTCOM_RESPONSE_USAGE;
	memset(upk_inv, 0xFF, crypto_box_PUBLICKEYBYTES); if (memeq(msg, upk_inv, crypto_box_PUBLICKEYBYTES)) return AEM_INTCOM_RESPONSE_USAGE;

	if (userNumFromUpk(msg) >= 0) return AEM_INTCOM_RESPONSE_EXIST;

	struct aem_user *user2 = realloc(user, (userCount + 1) * sizeof(struct aem_user));
	if (user2 == NULL) {syslog(LOG_ERR, "Failed allocaction"); return AEM_INTCOM_RESPONSE_ERR;}
	user = user2;

	bzero(&(user[userCount]), sizeof(struct aem_user));
	memcpy(user[userCount].upk, msg, crypto_box_PUBLICKEYBYTES);

	userCount++;
	saveUser();
	return AEM_INTCOM_RESPONSE_OK;
}

int32_t api_account_delete(const int num, const unsigned char * const msg, const size_t lenMsg) {
	if (msg == NULL || lenMsg != crypto_box_PUBLICKEYBYTES) return AEM_INTCOM_RESPONSE_ERR;

	const int delNum = userNumFromUpk(msg);
	if ((user[num].info & 3) != 3 && delNum != num) return AEM_INTCOM_RESPONSE_PERM; // Non-administrators can only delete themselves
	if (delNum < 0) return AEM_INTCOM_RESPONSE_NOTEXIST;
	if (delNum == 0) return AEM_INTCOM_RESPONSE_FORBID; // Forbid deleting the Master Administrator account

	if (delNum < (userCount - 1)) {
		const size_t s = sizeof(struct aem_user);
		memmove((unsigned char*)user + s * delNum, (unsigned char*)user + s * (delNum + 1), s * (userCount - delNum - 1));
	}

	userCount--;
	saveUser();
	return AEM_INTCOM_RESPONSE_OK;
}

int32_t api_account_update(const int num, const unsigned char * const msg, const size_t lenMsg) {
	if (msg == NULL || lenMsg != crypto_box_PUBLICKEYBYTES + 1) return AEM_INTCOM_RESPONSE_ERR;
	if (msg[0] > AEM_USERLEVEL_MAX) return AEM_INTCOM_RESPONSE_USAGE;

	const int updateNum = userNumFromUpk(msg + 1);
	if (updateNum < 0) return AEM_INTCOM_RESPONSE_USAGE;

	// If not admin && (updating another user || new-level >= current-level)
	if ((user[num].info & 3) != 3 && (updateNum != num || msg[0] >= (user[num].info & 3))) return AEM_INTCOM_RESPONSE_PERM;

	// Trying to set level to what it already is
	if ((user[updateNum].info & 3) == (msg[0] & 3)) return AEM_INTCOM_RESPONSE_USAGE;

	user[updateNum].info = (user[updateNum].info & 252) | (msg[0] & 3);
	saveUser();
	updateStorageLevels();
	return AEM_INTCOM_RESPONSE_OK;
}

int32_t api_address_create(const int num, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	const bool isShield = (lenMsg == 6 && memeq(msg, "SHIELD", 6));
	if (!isShield && lenMsg != 8) return AEM_INTCOM_RESPONSE_USAGE;

	int addrCount = user[num].info >> 3;
	if (addrCount >= AEM_ADDRESSES_PER_USER) return AEM_INTCOM_RESPONSE_LIMIT;

	unsigned char addr32[10];
	uint64_t hash = 0;
	if (isShield) {
		if (numAddresses(num, true) >= limits[user[num].info & 3][AEM_LIMIT_SHD]) return AEM_INTCOM_RESPONSE_LIMIT;

		randombytes_buf(addr32, 10);
		hash = addressToHash(addr32, true);
		if (hash == 0) return AEM_INTCOM_RESPONSE_EXIST;
	} else if (lenMsg == 8) { // Normal
		memcpy((unsigned char*)&hash, msg, 8);
		if (numAddresses(num, false) >= limits[user[num].info & 3][AEM_LIMIT_NRM]) return AEM_INTCOM_RESPONSE_LIMIT;

		if ((user[num].info & 3) != 3) {
			// Not admin, check if hash is forbidden
			for (unsigned int i = 0; i < AEM_HASH_ADMIN_COUNT; i++) {
				if (hash == AEM_HASH_ADMIN[i]) {
					hash = 0;
					break;
				}
			}
		}

		if (hash == 0 || hash == AEM_HASH_PUBLIC || hash == AEM_HASH_SYSTEM) return AEM_INTCOM_RESPONSE_EXIST;
	} else return AEM_INTCOM_RESPONSE_ERR;

	if (hashToUserNum(hash, isShield, NULL) >= 0) return AEM_INTCOM_RESPONSE_EXIST;

	user[num].addrHash[addrCount] = hash;
	user[num].addrFlag[addrCount] = isShield? (AEM_ADDR_FLAGS_DEFAULT | AEM_ADDR_FLAG_SHIELD) : AEM_ADDR_FLAGS_DEFAULT;
	addrCount++;
	user[num].info = (user[num].info & 3) + (addrCount << 3);

	saveUser();

	if (!isShield) return AEM_INTCOM_RESPONSE_OK;

	// Shield address
	*res = malloc(18);
	if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;
	memcpy(*res, (unsigned char*)&hash, 8);
	memcpy(*res + 8, addr32, 10);
	return 18;
}

int32_t api_address_delete(const int num, const unsigned char * const msg, const size_t lenMsg) {
	if (lenMsg != 8) return AEM_INTCOM_RESPONSE_ERR;

	unsigned char addrCount = user[num].info >> 3;
	int delNum = -1;
	for (int i = 0; i < addrCount; i++) {
		if (*(uint64_t*)msg == user[num].addrHash[i]) {
			delNum = i;
			break;
		}
	}

	if (delNum < 0) return AEM_INTCOM_RESPONSE_NOTEXIST;

	if (delNum < (addrCount - 1)) {
		for (int i = delNum; i < addrCount - 1; i++) {
			user[num].addrHash[i] = user[num].addrHash[i + 1];
			user[num].addrFlag[i] = user[num].addrFlag[i + 1];
		}
	}

	addrCount--;
	user[num].info = (user[num].info & 3) | (addrCount << 3);
	saveUser();
	return AEM_INTCOM_RESPONSE_OK;
}

int32_t api_address_update(const int num, const unsigned char * const msg, const size_t lenMsg) {
	if (lenMsg < 1 || lenMsg % 9 != 0) return AEM_INTCOM_RESPONSE_ERR;

	unsigned int found = 0;

	const int addrCount = user[num].info >> 3;
	for (size_t i = 0; i < (lenMsg / 9); i++) {
		for (int j = 0; j < addrCount; j++) {
			if (*(uint64_t*)(msg + (i * 9)) == user[num].addrHash[j]) {
				user[num].addrFlag[j] = (msg[(i * 9) + 8] & 63) | (user[num].addrFlag[j] & AEM_ADDR_FLAG_SHIELD);
				found++;
				break;
			}
		}
	}

	saveUser();

	if (found == lenMsg / 9) return AEM_INTCOM_RESPONSE_OK;
	else if (found > 0) return AEM_INTCOM_RESPONSE_PARTIAL;
	return AEM_INTCOM_RESPONSE_NOTEXIST;
}

int32_t api_private_update(const int num, const unsigned char * const msg, const size_t lenMsg) {
	if (lenMsg != AEM_LEN_PRIVATE) return AEM_INTCOM_RESPONSE_ERR;
	memcpy(user[num].private, msg, lenMsg);
	saveUser();
	return AEM_INTCOM_RESPONSE_OK;
}

int32_t api_setting_limits(const int num, const unsigned char * const msg, const size_t lenMsg) {
	if ((user[num].info & 3) != 3) return AEM_INTCOM_RESPONSE_PERM;
	if (lenMsg != 12) return AEM_INTCOM_RESPONSE_ERR;

	if (intcom(AEM_INTCOM_TYPE_STORAGE, AEM_ACC_STORAGE_LIMITS, (unsigned char[4]){msg[0], msg[3], msg[6], msg[9]}, 4, NULL, 0) != AEM_INTCOM_RESPONSE_OK) return AEM_INTCOM_RESPONSE_ERR;

	memcpy((unsigned char*)limits, msg, 12);
	saveSettings();
	return AEM_INTCOM_RESPONSE_OK;
}

int32_t api_internal_adrpk(const int num, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	if (lenMsg != 11) return AEM_INTCOM_RESPONSE_ERR;

	bool isShield = (msg[0] == 'S');
	const uint64_t hash = addressToHash(msg + 1, isShield);
	if (hash == 0) return AEM_INTCOM_RESPONSE_ERR;

	unsigned char flags;
	const int userNum = hashToUserNum(hash, isShield, &flags);
	if (userNum < 0 || ((user[num].info & 3) != 3 && (flags & AEM_ADDR_FLAG_ACCINT) == 0)) return AEM_INTCOM_RESPONSE_NOTEXIST;

	*res = malloc(crypto_box_PUBLICKEYBYTES);
	if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;

	memcpy(*res, user[userNum].upk, crypto_box_PUBLICKEYBYTES);
	return crypto_box_PUBLICKEYBYTES;
}

int32_t api_internal_level(const int num) {
	return -(user[num].info & 3);
}

int32_t api_internal_myadr(const int num, const unsigned char * const msg, const size_t lenMsg) {
	if (lenMsg != 11) return AEM_INTCOM_RESPONSE_ERR;

	bool isShield = (msg[0] == 'S');
	const uint64_t hash = addressToHash(msg + 1, isShield);
	if (hash == 0) return AEM_INTCOM_RESPONSE_ERR;

	const int userNum = hashToUserNum(hash, isShield, NULL);
	return (userNum == num) ? AEM_INTCOM_RESPONSE_OK : AEM_INTCOM_RESPONSE_NOTEXIST;
}

int32_t api_internal_uinfo(const int num, unsigned char **res) {
	*res = malloc(AEM_MAXLEN_UINFO);
	if (*res == NULL) {syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}

	size_t lenRes = 4;
	(*res)[0] = user[num].info;
	memcpy(*res + 1, limits[user[num].info & 3], 3);

	for (int i = 0; i < (user[num].info >> 3); i++) {
		memcpy(*res + lenRes, &(user[num].addrHash[i]), 8);
		(*res)[lenRes + 8] = user[num].addrFlag[i];
		lenRes += 9;
	}

	memcpy(*res + lenRes, user[num].private, AEM_LEN_PRIVATE);
	lenRes += AEM_LEN_PRIVATE;
	return lenRes;
}

int32_t api_internal_pubks(const int num, unsigned char **res) {
	if ((user[num].info & 3) != 3) return AEM_INTCOM_RESPONSE_PERM;

	*res = malloc(userCount * crypto_box_PUBLICKEYBYTES);
	if (*res == NULL) {syslog(LOG_ERR, "Failed allocation"); return AEM_INTCOM_RESPONSE_ERR;}

	for (int i = 0; i < userCount; i++) {
		memcpy(*res + (i * crypto_box_PUBLICKEYBYTES), user[i].upk, crypto_box_PUBLICKEYBYTES);
	}

	return userCount * crypto_box_PUBLICKEYBYTES;
}

int32_t mta_getUpk(const unsigned char * const addr32, const bool isShield, unsigned char **res) {
	const uint64_t hash = addressToHash(addr32, isShield);
	if (hash == 0) return AEM_INTCOM_RESPONSE_ERR;

	unsigned char flags;
	const int userNum = hashToUserNum(hash, isShield, &flags);
	if (userNum < 0 && isShield) return AEM_INTCOM_RESPONSE_NOTEXIST;
	flags &= (AEM_ADDR_FLAG_ACCEXT | AEM_ADDR_FLAG_ALLVER | AEM_ADDR_FLAG_ATTACH | AEM_ADDR_FLAG_SECURE | AEM_ADDR_FLAG_ORIGIN);

	// Prepare fake response
	uint64_t htHash = 0;
	crypto_shorthash((unsigned char*)&htHash, addr32, 10, saltShield);
	if (time(NULL) > fakeFlag_expire[htHash & (AEM_FAKEFLAGS_HTSIZE - 1)]) {
		fakeFlag_expire[htHash & (AEM_FAKEFLAGS_HTSIZE - 1)] = time(NULL) + randombytes_uniform(AEM_FAKEFLAGS_MAXTIME);
	}

	uint64_t fakeHash = 0;
	crypto_shorthash((unsigned char*)&fakeHash, (unsigned char*)&fakeFlag_expire[htHash & (AEM_FAKEFLAGS_HTSIZE - 1)], 4, saltShield);

	unsigned char fakeFlags = 0;
	if (((fakeHash >>  0) & 7) == 0) fakeFlags |= AEM_ADDR_FLAG_ALLVER; // 12.5% chance (1 in 8)
	if (((fakeHash >>  8) & 7) == 0) fakeFlags |= AEM_ADDR_FLAG_ATTACH; // 12.5% chance (1 in 8)
	if (((fakeHash >> 16) & 7) == 0) fakeFlags |= AEM_ADDR_FLAG_SECURE; // 12.5% chance (1 in 8)
	if (((fakeHash >> 24) & 7) == 0) fakeFlags |= AEM_ADDR_FLAG_ORIGIN; // 12.5% chance (1 in 8)

	unsigned char empty[crypto_box_PUBLICKEYBYTES];
	sodium_memzero(empty, crypto_box_PUBLICKEYBYTES);

	// Respond
	*res = malloc(crypto_box_PUBLICKEYBYTES + 1);
	if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;

	const bool sendFake = (userNum < 0 || (flags & AEM_ADDR_FLAG_ACCEXT) == 0);
	memcpy(*res, sendFake? empty : user[userNum].upk, crypto_box_PUBLICKEYBYTES);
	(*res)[crypto_box_PUBLICKEYBYTES] = sendFake? fakeFlags : flags;
	return crypto_box_PUBLICKEYBYTES + 1;
}
