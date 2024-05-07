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

#include "../Global.h"
#include "../Common/api_req.h"
#include "../Common/memeq.h"
#include "../IntCom/Client.h"
#include "../IntCom/Server.h"
#include "../api/Error.h"

#include "aem_user.h"

#include "IO.h"

#define AEM_FAKEFLAGS_HTSIZE 2048
#define AEM_FAKEFLAGS_MAXTIME 2000000 // 23d

#define AEM_LIMIT_MIB 0
#define AEM_LIMIT_NRM 1
#define AEM_LIMIT_SHD 2

#ifdef AEM_ADDRESS_NOPWHASH
	#define AEM_SALTNORMAL_LEN crypto_shorthash_KEYBYTES
#else
	#define AEM_SALTNORMAL_LEN crypto_pwhash_SALTBYTES
#endif

static struct aem_user *users = NULL;

static unsigned char accountKey[crypto_aead_aegis256_KEYBYTES];
static unsigned char saltNormal[AEM_SALTNORMAL_LEN];
static unsigned char saltShield[crypto_shorthash_KEYBYTES];
static uint64_t addrHash_system = 0;
static uint32_t fakeFlag_expire[AEM_FAKEFLAGS_HTSIZE];

static unsigned char limits[4][3] = {
// MiB, Nrm, Shd
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{UINT8_MAX, AEM_ADDRESSES_PER_USER, AEM_ADDRESSES_PER_USER} // Admin
};

uint16_t api_uid = 0;
unsigned char api_resBodyKey[AEM_API_BODY_KEYSIZE];
unsigned char api_reqBodyKey[AEM_API_BODY_KEYSIZE];

static void saveSettings(void) {
	const size_t lenEnc = 12 + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);

	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, (unsigned char*)limits, 12, NULL, 0, NULL, enc, accountKey);

	const int fd = open("Settings.aem", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "Failed opening Settings.aem"); return;}

	const ssize_t ret = write(fd, enc, lenEnc);
	close(fd);
	if (ret != (ssize_t)lenEnc) syslog(LOG_ERR, "Failed writing Settings.aem");
}

static int loadSettings(void) {
	const int fd = open("Settings.aem", O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) return -1;

	const off_t lenEnc = lseek(fd, 0, SEEK_END);
	const off_t lenDec = lenEnc - crypto_aead_aegis256_NPUBBYTES - crypto_aead_aegis256_ABYTES;
	if (lenDec != 12) {syslog(LOG_WARNING, "Failed loading Settings.aem - invalid size"); close(fd); return -1;}

	unsigned char enc[lenEnc];
	if (pread(fd, enc, lenEnc, 0) != lenEnc) {
		close(fd);
		syslog(LOG_WARNING, "Failed loading Settings.aem - failed read");
		return -1;
	}
	close(fd);

	if (crypto_aead_aegis256_decrypt((unsigned char*)limits, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, lenEnc - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, accountKey) != 0) return -1;
	return 0;
}

static void saveUser(void) {
	const size_t lenClear = sizeof(struct aem_user) * AEM_USERCOUNT;

	const size_t lenEnc = lenClear + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char * const enc = malloc(lenEnc);
	if (enc == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);

	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, (unsigned char*)users, lenClear, NULL, 0, NULL, enc, accountKey);

	const int fd = open("Account.aem", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {
		free(enc);
		syslog(LOG_ERR, "Failed opening Account.aem");
		return;
	}

	const ssize_t ret = write(fd, enc, lenEnc);
	free(enc);
	close(fd);

	if (ret != (ssize_t)lenEnc) syslog(LOG_ERR, "Failed writing Account.aem");
}

static int loadUser(void) {
	if (users != NULL) {syslog(LOG_ERR, "Account data already loaded"); return -1;}

	const int fd = open("Account.aem", O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "Failed opening Account.aem: %m"); return -1;}

	const off_t lenEnc = lseek(fd, 0, SEEK_END);
	const off_t lenDec = lenEnc - crypto_aead_aegis256_NPUBBYTES - crypto_aead_aegis256_ABYTES;
	if (lenDec != AEM_USERCOUNT * sizeof(struct aem_user)) {
		close(fd);
		syslog(LOG_ERR, "Invalid size for Account.aem");
		return -1;
	}

	unsigned char * const enc = malloc(lenEnc);
	if (enc == NULL) {close(fd); syslog(LOG_ERR, "Failed allocation"); return -1;}
	if (pread(fd, enc, lenEnc, 0) != lenEnc) {
		close(fd);
		free(enc);
		syslog(LOG_ERR, "Failed reading Account.aem");
		return -1;
	}
	close(fd);

	users = malloc(lenDec);
	if (users == NULL) {syslog(LOG_ERR, "Failed allocation"); free(enc); return -1;}

	if (crypto_aead_aegis256_decrypt((unsigned char*)users, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, lenEnc - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, accountKey) == -1) {
		free(users);
		syslog(LOG_ERR, "Failed decrypting Account.aem");
		return -1;
	}

	return 0;
}

static uint16_t hashToUid(const uint64_t hash, const bool isShield, unsigned char * const flagp) {
	for (int uid = 0; uid < AEM_USERCOUNT; uid++) {
		for (int addrNum = 0; addrNum < users[uid].addrCount; addrNum++) {
			if (hash == users[uid].addrHash[addrNum] && (users[uid].addrFlag[addrNum] & AEM_ADDR_FLAG_SHIELD) == (isShield? AEM_ADDR_FLAG_SHIELD : 0)) {
				if (flagp != NULL) *flagp = users[uid].addrFlag[addrNum];
				return uid;
			}
		}
	}

	return UINT16_MAX;
}

__attribute__((warn_unused_result))
static uint64_t addressToHash(const unsigned char * const addr32, const bool shield) {
	if (addr32 == NULL) return 0;

	if (shield) {
		if (memeq(addr32 + 2, AEM_ADDR32_ADMIN, 8)) return 0; // Forbid addresses ending with 'administrator'
		uint64_t hash;
		crypto_shorthash((unsigned char*)&hash, addr32, AEM_ADDR32_BINLEN, saltShield);
		return hash;
	} else if (memeq(addr32, AEM_ADDR32_SYSTEM, AEM_ADDR32_BINLEN)) return 0; // Forbid 'system'

#ifdef AEM_ADDRESS_NOPWHASH
	uint64_t hash;
	crypto_shorthash((unsigned char*)&hash, addr32, AEM_ADDR32_BINLEN, saltNormal);
	return hash;
#else
	uint64_t halves[2];
	if (crypto_pwhash((unsigned char*)halves, sizeof(uint64_t) * 2, (const char*)addr32, AEM_ADDR32_BINLEN, saltNormal, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) {
		syslog(LOG_ERR, "Failed hashing address");
		return 0;
	}
	return halves[0] ^ halves[1];
#endif
}

static int numAddresses(const int uid, const bool shield) {
	int counter = 0;

	for (int i = 0; i < users[uid].addrCount; i++) {
		const bool isShield = (users[uid].addrFlag[i] & AEM_ADDR_FLAG_SHIELD) > 0;
		if (isShield == shield) counter++;
	}

	return counter;
}

// API: Special
static int32_t api_response_status(unsigned char * const res, const unsigned char status) {
	res[0] = status;
	return 1;
}

int32_t api_invalid(unsigned char * const res) {
	return api_response_status(res, AEM_API_ERR_CMD);
}

// API: GET
int32_t api_account_browse(unsigned char * const res) {
	memcpy(res, (unsigned char*)limits, 12);

	for (int i = 0; i < AEM_USERCOUNT; i++) {
		const uint32_t kib = (sodium_is_zero(users[i].uak, AEM_KDF_KEYSIZE) == 1) ? 0 : 1234567; // TODO

		const uint32_t u32 = users[i].level | (numAddresses(i, false) << 2) | (numAddresses(i, true) << 7) | (kib << 12);
		memcpy(res + 12 + (i * sizeof(uint32_t)), (const unsigned char * const)&u32, sizeof(uint32_t));
	}

	return 12 + (AEM_USERCOUNT * sizeof(uint32_t));
}

int32_t api_account_delete(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	const uint16_t del_uid = *(const uint16_t * const)reqData;
	if (del_uid == 0) return api_response_status(res, AEM_API_ERR_ACCOUNT_FORBIDMASTER);
	if (del_uid >= AEM_USERCOUNT) return api_response_status(res, AEM_API_ERR_PARAM);
	if (users[api_uid].level != AEM_USERLEVEL_MAX && api_uid != del_uid) return api_response_status(res, AEM_API_ERR_LEVEL);
	if (sodium_is_zero(users[del_uid].uak, AEM_KDF_KEYSIZE) == 1) {return api_response_status(res, AEM_API_ERR_ACCOUNT_NOTEXIST);}

	sodium_memzero(users + del_uid, sizeof(struct aem_user));
	saveUser();

	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, AEM_ACC_STORAGE_DELETE, reqData, sizeof(uint16_t), NULL, 0);
	return api_response_status(res, (icRet == AEM_INTCOM_RESPONSE_OK) ? AEM_API_STATUS_OK : AEM_API_ERR_ACCOUNT_DELETE_NOSTORAGE);
}

int32_t api_account_update(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	const uint16_t upd_uid = *(const uint16_t * const)reqData;
	const uint8_t new_lvl = reqData[2];
	if (upd_uid == 0) return api_response_status(res, AEM_API_ERR_ACCOUNT_FORBIDMASTER);
	if (upd_uid >= AEM_USERCOUNT) return api_response_status(res, AEM_API_ERR_PARAM);
	if (users[api_uid].level != AEM_USERLEVEL_MAX && (api_uid != upd_uid || new_lvl > users[api_uid].level)) return api_response_status(res, AEM_API_ERR_LEVEL);
	if (sodium_is_zero(users[upd_uid].uak, AEM_KDF_KEYSIZE) == 1) {return api_response_status(res, AEM_API_ERR_ACCOUNT_NOTEXIST);}

	users[upd_uid].level = new_lvl;
	saveUser();
	return api_response_status(res, AEM_API_STATUS_OK);
}

int32_t api_address_create(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	const bool isShield = (sodium_is_zero(reqData, 8) == 1);
	if (users[api_uid].addrCount >= AEM_ADDRESSES_PER_USER) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_ATLIMIT);

	unsigned char addr32[10];
	uint64_t hash = 0;
	if (isShield) {
		if (numAddresses(api_uid, true) >= limits[users[api_uid].level][AEM_LIMIT_SHD]) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_ATLIMIT);

		randombytes_buf(addr32, 10);
		hash = addressToHash(addr32, true);
		if (hash == 0) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_INUSE);
	} else { // Normal
		if (numAddresses(api_uid, false) >= limits[users[api_uid].level][AEM_LIMIT_NRM]) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_ATLIMIT);

		memcpy((unsigned char*)&hash, reqData, 8);

/*
		if (users[api_uid].level != AEM_USERLEVEL_MAX) {
			// Not admin, check if hash is forbidden
			for (unsigned int i = 0; i < AEM_HASH_ADMIN_COUNT; i++) {
				if (hash == AEM_HASH_ADMIN[i]) {
					hash = 0;
					break;
				}
			}
		}
*/

		if (hash == 0 || hash == addrHash_system) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_INUSE);
	}

	if (hashToUid(hash, isShield, NULL) != UINT16_MAX) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_INUSE);

	users[api_uid].addrHash[users[api_uid].addrCount] = hash;
	users[api_uid].addrFlag[users[api_uid].addrCount] = isShield? (AEM_ADDR_FLAGS_DEFAULT | AEM_ADDR_FLAG_SHIELD) : AEM_ADDR_FLAGS_DEFAULT;
	users[api_uid].addrCount++;

	saveUser();

	if (!isShield) return api_response_status(res, AEM_API_STATUS_OK);

	// Shield address - send hash and address
	memcpy(res, (unsigned char*)&hash, 8);
	memcpy(res + 8, addr32, 10);
	return 18;
}

int32_t api_address_delete(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	int delNum = -1;
	for (int i = 0; i < users[api_uid].addrCount; i++) {
		if (memeq(reqData, (unsigned char*)&users[api_uid].addrHash[i], sizeof(uint64_t))) {
			delNum = i;
			break;
		}
	}

	if (delNum < 0) return api_response_status(res, AEM_API_ERR_ACCOUNT_NOTEXIST);

	if (delNum < (users[api_uid].addrCount - 1)) {
		for (int i = delNum; i < users[api_uid].addrCount - 1; i++) {
			users[api_uid].addrHash[i] = users[api_uid].addrHash[i + 1];
			users[api_uid].addrFlag[i] = users[api_uid].addrFlag[i + 1];
		}
	}

	users[api_uid].addrCount--;
	saveUser();
	return api_response_status(res, AEM_API_STATUS_OK);
}

int32_t api_address_update(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	memcpy(users[api_uid].addrFlag, (unsigned char[]){
		(users[api_uid].addrFlag[0]  & 192) |  (reqData[0]  &  63),
		(users[api_uid].addrFlag[1]  & 192) | ((reqData[0]  & 192) >> 2) | (reqData[1]  & 15),
		(users[api_uid].addrFlag[2]  & 192) | ((reqData[1]  & 240) >> 2) | (reqData[2]  &  3),
		(users[api_uid].addrFlag[3]  & 192) | ((reqData[2]  & 252) >> 2),
		(users[api_uid].addrFlag[4]  & 192) |  (reqData[3]  &  63),
		(users[api_uid].addrFlag[5]  & 192) | ((reqData[3]  & 192) >> 2) | (reqData[4]  & 15),
		(users[api_uid].addrFlag[6]  & 192) | ((reqData[4]  & 240) >> 2) | (reqData[5]  &  3),
		(users[api_uid].addrFlag[7]  & 192) | ((reqData[5]  & 252) >> 2),
		(users[api_uid].addrFlag[8]  & 192) |  (reqData[6]  &  63),
		(users[api_uid].addrFlag[9]  & 192) | ((reqData[6]  & 192) >> 2) | (reqData[7]  & 15),
		(users[api_uid].addrFlag[10] & 192) | ((reqData[7]  & 240) >> 2) | (reqData[8]  &  3),
		(users[api_uid].addrFlag[11] & 192) | ((reqData[8]  & 252) >> 2),
		(users[api_uid].addrFlag[12] & 192) |  (reqData[9]  &  63),
		(users[api_uid].addrFlag[13] & 192) | ((reqData[9]  & 192) >> 2) | (reqData[10]  & 15),
		(users[api_uid].addrFlag[14] & 192) | ((reqData[10] & 240) >> 2) | (reqData[11]  &  3),
		(users[api_uid].addrFlag[15] & 192) | ((reqData[11] & 252) >> 2),
		(users[api_uid].addrFlag[16] & 192) |  (reqData[12] &  63),
		(users[api_uid].addrFlag[17] & 192) | ((reqData[12] & 192) >> 2) | (reqData[13]  & 15),
		(users[api_uid].addrFlag[18] & 192) | ((reqData[13] & 240) >> 2) | (reqData[14]  &  3),
		(users[api_uid].addrFlag[19] & 192) | ((reqData[14] & 252) >> 2),
		(users[api_uid].addrFlag[20] & 192) |  (reqData[15] &  63),
		(users[api_uid].addrFlag[21] & 192) | ((reqData[15] & 192) >> 2) | (reqData[16]  & 15),
		(users[api_uid].addrFlag[22] & 192) | ((reqData[16] & 240) >> 2) | (reqData[17]  &  3),
		(users[api_uid].addrFlag[23] & 192) | ((reqData[17] & 252) >> 2),
		(users[api_uid].addrFlag[24] & 192) |  (reqData[18] &  63),
		(users[api_uid].addrFlag[25] & 192) | ((reqData[18] & 192) >> 2) | (reqData[19]  & 15),
		(users[api_uid].addrFlag[26] & 192) | ((reqData[19] & 240) >> 2) | (reqData[20]  &  3),
		(users[api_uid].addrFlag[27] & 192) | ((reqData[20] & 252) >> 2),
		(users[api_uid].addrFlag[28] & 192) |  (reqData[21] &  63),
		(users[api_uid].addrFlag[29] & 192) | ((reqData[21] & 192) >> 2) | (reqData[22]  & 15),
		(users[api_uid].addrFlag[30] & 192) | ((reqData[22] & 240) >> 2) | (reqData[23]  &  3)
		// Last 6 bits unused
	}, AEM_ADDRESSES_PER_USER);

	saveUser();
	return api_response_status(res, AEM_API_STATUS_OK);
}

int32_t api_message_browse(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	if ((reqData[0] & AEM_API_MESSAGE_BROWSE_FLAG_UINFO) == 0) return 0; // User data not requested, nothing to do

	// User data requested, add it to the response
	res[0] = users[api_uid].level | (users[api_uid].addrCount << 2);
	memcpy(res + 1, limits[users[api_uid].level], 3);

	for (int i = 0; i < users[api_uid].addrCount; i++) {
		memcpy(res + (i * 9) + 4, (unsigned char*)&users[api_uid].addrHash[i], sizeof(uint64_t));
		res[(i * 9) + 12] = users[api_uid].addrFlag[i];
	}

	memcpy(res + 4 + (users[api_uid].addrCount * 9), users[api_uid].private, AEM_LEN_PRIVATE);
	memcpy(res + 4 + (users[api_uid].addrCount * 9) + AEM_LEN_PRIVATE, saltNormal, AEM_SALTNORMAL_LEN);
#ifdef AEM_ADDRESS_NOPWHASH
	bzero(res + 4 + (users[api_uid].addrCount * 9) + AEM_LEN_PRIVATE + AEM_SALTNORMAL_LEN, 5);
#else
	const uint32_t mlim = AEM_ADDRESS_ARGON2_MEMLIMIT;
	res[4 + (users[api_uid].addrCount * 9) + AEM_LEN_PRIVATE + AEM_SALTNORMAL_LEN] = AEM_ADDRESS_ARGON2_OPSLIMIT;
	memcpy(res + 5 + (users[api_uid].addrCount * 9) + AEM_LEN_PRIVATE + AEM_SALTNORMAL_LEN, (const unsigned char*)&mlim, sizeof(uint32_t));
#endif

	return 5 + (users[api_uid].addrCount * 9) + AEM_LEN_PRIVATE + crypto_pwhash_SALTBYTES + sizeof(uint32_t);
}

int32_t api_setting_limits(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	memcpy(limits, reqData, 12);
	saveSettings();
	return api_response_status(res, AEM_API_STATUS_OK);
}

// API: POST (Continue)
int32_t api_account_create(unsigned char * const res, const unsigned char * const data, const size_t lenData) {
	if (lenData != AEM_KDF_KEYSIZE + X25519_PKBYTES) return api_response_status(res, AEM_API_ERR_PARAM);
	const uint16_t newUid = aem_getUserId(data);
	if (sodium_is_zero(users[newUid].uak, AEM_KDF_KEYSIZE) != 1) {return api_response_status(res, AEM_API_ERR_ACCOUNT_EXIST);}

	memcpy(users[newUid].uak, data, AEM_KDF_KEYSIZE);
	memcpy(users[newUid].epk, data + AEM_KDF_KEYSIZE, X25519_PKBYTES);

	unsigned char icMsg[sizeof(uint16_t) + X25519_PKBYTES];
	memcpy(icMsg, (const unsigned char * const)&newUid, sizeof(uint16_t));
	memcpy(icMsg + sizeof(uint16_t), data + AEM_KDF_KEYSIZE, X25519_PKBYTES);
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, AEM_ACC_STORAGE_CREATE, icMsg, sizeof(uint16_t) + X25519_PKBYTES, NULL, 0);

	saveUser();
	return api_response_status(res, (icRet == AEM_INTCOM_RESPONSE_OK) ? AEM_API_STATUS_OK : AEM_API_ERR_INTERNAL);
}

int32_t api_private_update(unsigned char * const res, const unsigned char * const data, const size_t lenData) {
	if (lenData != AEM_LEN_PRIVATE) return api_response_status(res, AEM_API_ERR_PARAM);
	memcpy(users[api_uid].private, data, lenData);
	saveUser();
	return api_response_status(res, AEM_API_STATUS_OK);
}

// API: POST (Status)
int32_t api_message_create(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	if (reqData[21] == 0x01 && reqData[22] == 0x02 && reqData[23] == 0x03) { // IntMsg
		// Verify user owns their sending address
		bool shield = (reqData[20] & 128) != 0;
		if (api_uid != hashToUid(addressToHash(reqData, shield), shield, NULL)) {
			return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_INT_OWN_ADDR);
		}

		// Get recipient address
		shield = ((reqData[20] & 64) != 0);
		const uint64_t hash = addressToHash(reqData + 10, shield);
		if (hash == 0) return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_INT_REC_DENY); // Invalid address

		unsigned char flags = 0;
		const uint16_t uid = hashToUid(hash, shield, &flags);
		if (uid == UINT16_MAX) return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_INT_REC_DENY); // Address not registered
		if ((flags & AEM_ADDR_FLAG_ACCINT) == 0) return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_INT_REC_DENY); // Recipient does not accept internal mail

		memcpy(res, (const unsigned char*)&uid, sizeof(uint16_t));
		return 2;
	} else {
		// Email
		return api_response_status(res, AEM_API_ERR_INTERNAL); // TODO
	}
}

//
static void uak_derive(unsigned char * const out, const int lenOut, const uint64_t binTs, const uint16_t uid, const bool post, const unsigned long long type) {
	aem_kdf(out, lenOut, binTs | (post? (128LLU << 40) : 0) | (type << 40), users[uid].uak);
}

static bool auth_binTs(const uint16_t uid, const uint64_t reqBinTs) {
	uint64_t prevBinTs = 0;
	memcpy((unsigned char*)&prevBinTs, users[uid].lastBinTs, 5);
	return (reqBinTs > prevBinTs);
}

void updateBinTs(const uint16_t uid, uint64_t reqBinTs) {
	memcpy(users[uid].lastBinTs, (const unsigned char*)&reqBinTs, 5);
}

bool api_auth(unsigned char * const res, struct aem_req * const req, const bool post) {
	// Authenticate
	unsigned char req_key_auth[crypto_onetimeauth_KEYBYTES];
	uak_derive(req_key_auth, crypto_onetimeauth_KEYBYTES, req->binTs, req->uid, post, AEM_UAK_TYPE_URL_AUTH);
	if (crypto_onetimeauth_verify(req->mac, (unsigned char*)req + 5, AEM_API_REQ_LEN - crypto_onetimeauth_BYTES - 5, req_key_auth) != 0) return false;
	if (!auth_binTs(req->uid, req->binTs)) return false;

	// Decrypt
	unsigned char req_key_data[2 + AEM_API_REQ_DATA_LEN];
	uak_derive(req_key_data, 2 + AEM_API_REQ_DATA_LEN, req->binTs, req->uid, post, AEM_UAK_TYPE_URL_DATA);

	req->cmd ^= req_key_data[0] & 15;
	req->flags ^= req_key_data[1];

	for (int i = 0; i < AEM_API_REQ_DATA_LEN; i++) {
		req->data[i] ^= req_key_data[2 + i];
	}

	// Copy data to the base response
	res[0] = req->cmd;
	memcpy(res + 1, req->data, AEM_API_REQ_DATA_LEN);
	uak_derive(res + 1 + AEM_API_REQ_DATA_LEN, AEM_API_BODY_KEYSIZE, req->binTs, req->uid, post, AEM_UAK_TYPE_BODY_REQ);
	uak_derive(res + 1 + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE, AEM_API_BODY_KEYSIZE, req->binTs, req->uid, post, AEM_UAK_TYPE_BODY_RES);

	api_uid = req->uid;
	return true;
}

// MTA
int32_t mta_getUid(const unsigned char * const addr32, const bool isShield, unsigned char **res) {
	const uint64_t hash = addressToHash(addr32, isShield);
	if (hash == 0) return AEM_INTCOM_RESPONSE_ERR;

	unsigned char flags = 0;
	const uint16_t uid = hashToUid(hash, isShield, &flags);
	if (uid == UINT16_MAX) {
		if (isShield) return AEM_INTCOM_RESPONSE_NOTEXIST;

		// Normal addresses always act as if they exist
		*res = malloc(3);
		if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;
		memset(*res, 0xFF, 3);
		return 3;
	}

	*res = malloc(3);
	if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;
	memcpy(*res, (const unsigned char * const)&uid, sizeof(uint16_t));
	(*res)[sizeof(uint16_t)] = flags & (AEM_ADDR_FLAG_ACCEXT | AEM_ADDR_FLAG_ALLVER | AEM_ADDR_FLAG_ATTACH | AEM_ADDR_FLAG_SECURE | AEM_ADDR_FLAG_ORIGIN);

	return 3;
}

// Storage
int32_t sto_uid2epk(const uint16_t uid, unsigned char **res) {
	*res = malloc(X25519_PKBYTES);
	if (*res == NULL) {syslog(LOG_ERR, "Failed malloc"); return AEM_INTCOM_RESPONSE_ERR;}

	memcpy(*res, users[uid].epk, X25519_PKBYTES);
	return X25519_PKBYTES;
}

// Setup
void ioFree(void) {
	sodium_memzero(accountKey, crypto_aead_aegis256_KEYBYTES);
	sodium_memzero(saltShield, crypto_shorthash_KEYBYTES);
	sodium_memzero(users, sizeof(struct aem_user) * AEM_USERCOUNT);
	free(users);
}

int ioSetup(const unsigned char baseKey[AEM_KDF_KEYSIZE]) {
	aem_kdf(accountKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_ACC_ACC, baseKey);
	aem_kdf(saltNormal, AEM_SALTNORMAL_LEN,            AEM_KDF_KEYID_ACC_NRM, baseKey);
	aem_kdf(saltShield, crypto_shorthash_KEYBYTES,     AEM_KDF_KEYID_ACC_SHD, baseKey);

#ifdef AEM_ADDRESS_NOPWHASH
	uint64_t hash;
	crypto_shorthash((unsigned char*)&hash, AEM_ADDR32_SYSTEM, AEM_ADDR32_BINLEN, saltNormal);
	addrHash_system = hash;
#else
	uint64_t halves[2];
	if (crypto_pwhash((unsigned char*)halves, sizeof(uint64_t) * 2, (const char*)AEM_ADDR32_SYSTEM, AEM_ADDR32_BINLEN, saltNormal, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) {
		syslog(LOG_ERR, "Failed hashing system address");
		return 0;
	}
	addrHash_system = halves[0] ^ halves[1];
#endif

	if (loadUser() != 0) return -1;
	loadSettings(); // Ignore errors
//	bzero((unsigned char*)fakeFlag_expire, 4 * AEM_FAKEFLAGS_HTSIZE);

//	if (intcom(AEM_INTCOM_SERVER_STO, AEM_ACC_STORAGE_LIMITS, (unsigned char[4]){limits[0][0], limits[1][0], limits[2][0], limits[3][0]}, 4, NULL, 0) != AEM_INTCOM_RESPONSE_OK) {
//		syslog(LOG_ERR, "ioSetup: intcom failed");
//		return -1;
//	}

	return 0;
}
