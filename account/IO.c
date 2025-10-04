#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/Addr32.h"
#include "../Common/api_req.h"
#include "../Common/binTs.h"
#include "../Common/evpKeys.h"
#include "../Common/memeq.h"
#include "../Data/address.h"
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

enum {
	AEM_UAK_TYPE_URL_AUTH,
	AEM_UAK_TYPE_URL_DATA,
	AEM_UAK_TYPE_BODY_REQ,
	AEM_UAK_TYPE_BODY_RES
};

static struct aem_user *user[AEM_USERCOUNT];

size_t lenRsaAdminKey;
size_t lenRsaUsersKey;
static unsigned char rsaAdminKey[4096];
static unsigned char rsaUsersKey[4096];

static unsigned char accountKey[crypto_aead_aegis256_KEYBYTES];
static unsigned char saltNormal[AEM_SALTNORMAL_LEN];
static unsigned char saltShield[crypto_shorthash_KEYBYTES];
static unsigned char key_srk[AEM_KDF_SUB_KEYLEN];
static uint32_t fakeFlag_expire[AEM_FAKEFLAGS_HTSIZE];

static unsigned char limits[4][3] = {
// MiB, Nrm, Shd
	{0, 0, 0},
	{0, 0, 0},
	{0, 0, 0},
	{UINT8_MAX, AEM_ADDRESSES_PER_USER, AEM_ADDRESSES_PER_USER} // Admin
};

uint16_t api_uid = 0;

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
	int userCount = 0;
	for (int i = 0; i < AEM_USERCOUNT; i++) {
		if (user[i] != NULL) userCount++;
	}

	const size_t lenDec = (sizeof(struct aem_user) + sizeof(uint16_t)) * userCount;
	unsigned char * const dec = malloc(lenDec);
	if (dec == NULL) {syslog(LOG_ERR, "Failed allocation"); return;}

	userCount = 0;
	for (uint16_t i = 0; i < AEM_USERCOUNT; i++) {
		if (user[i] == NULL) continue;

		memcpy(dec + (userCount * (sizeof(struct aem_user) + sizeof(uint16_t))), &i, sizeof(uint16_t));
		memcpy(dec + (userCount * (sizeof(struct aem_user) + sizeof(uint16_t))) + sizeof(uint16_t), user[i], sizeof(struct aem_user));
		userCount++;
	}

	const size_t lenEnc = lenDec + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES;
	unsigned char * const enc = malloc(lenEnc);
	if (enc == NULL) {syslog(LOG_ERR, "Failed allocation"); free(dec); return;}
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, dec, lenDec, NULL, 0, NULL, enc, accountKey);
	free(dec);

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
	const int fd = open("Account.aem", O_RDONLY | O_CLOEXEC | O_NOATIME | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0) {syslog(LOG_ERR, "Failed opening Account.aem: %m"); return -1;}

	const off_t lenEnc = lseek(fd, 0, SEEK_END);
	const off_t lenDec = lenEnc - crypto_aead_aegis256_NPUBBYTES - crypto_aead_aegis256_ABYTES;
	if (lenDec % (sizeof(struct aem_user) + sizeof(uint16_t)) != 0) {
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

	unsigned char * const dec = malloc(lenDec);
	if (dec == NULL) {free(enc); syslog(LOG_ERR, "Failed allocation"); return -1;}
	if (crypto_aead_aegis256_decrypt(dec, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, lenEnc - crypto_aead_aegis256_NPUBBYTES, NULL, 0, enc, accountKey) == -1) {
		free(enc);
		free(dec);
		syslog(LOG_ERR, "Failed decrypting Account.aem");
		return -1;
	}
	free(enc);

	const int userCount = lenDec / (sizeof(struct aem_user) + sizeof(uint16_t));
	for (int i = 0; i < userCount; i++) {
		uint16_t uid;
		memcpy(&uid, dec + (i * (sizeof(struct aem_user) + sizeof(uint16_t))), sizeof(uint16_t));
		if (uid >= AEM_USERCOUNT) {free(dec); syslog(LOG_ERR, "Invalid UserID: %u", uid); return -1;}

		user[uid] = malloc(sizeof(struct aem_user));
		if (user[uid] == NULL) {syslog(LOG_INFO, "Failed allocation"); continue;}
		memcpy(user[uid], dec + (i * (sizeof(struct aem_user) + sizeof(uint16_t))) + sizeof(uint16_t), sizeof(struct aem_user));
	}

	free(dec);
	return 0;
}

static uint16_t hashToUid(const uint64_t hash, const bool isShield, unsigned char * const flagp) {
	for (int uid = 0; uid < AEM_USERCOUNT; uid++) {
		if (user[uid] == NULL) continue;

		for (int addrNum = 0; addrNum < user[uid]->addrCount; addrNum++) {
			if (hash == user[uid]->addrHash[addrNum] && (user[uid]->addrFlag[addrNum] & AEM_ADDR_FLAG_SHIELD) == (isShield? AEM_ADDR_FLAG_SHIELD : 0)) {
				if (flagp != NULL) *flagp = user[uid]->addrFlag[addrNum];
				return uid;
			}
		}
	}

	return UINT16_MAX;
}

__attribute__((warn_unused_result))
static uint64_t addressToHash(const unsigned char * const addr32) {
	if (addr32 == NULL) return 0;

	if ((addr32[0] & 128) != 0) {
		// Shield
		if (memeq(addr32 + 2, AEM_ADDR32_ADMIN, 8)) return 0; // Forbid addresses ending with 'administrator'
		uint64_t hash;
		crypto_shorthash((unsigned char*)&hash, addr32, AEM_ADDR32_BINLEN, saltShield);
		return hash;
	}

	// Normal
	if (memeq(addr32, AEM_ADDR32_SYSTEM, AEM_ADDR32_BINLEN)) return 0; // Forbid 'system'
	if (addr32[0] >> 3 == 0) return 0; // Forbid zero length

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

	for (int i = 0; i < user[uid]->addrCount; i++) {
		const bool isShield = (user[uid]->addrFlag[i] & AEM_ADDR_FLAG_SHIELD) > 0;
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
		if (user[i] != NULL) {
			const uint32_t kib = 1234567; // TODO
			const uint32_t u32 = user[i]->level | (numAddresses(i, false) << 2) | (numAddresses(i, true) << 7) | (kib << 12);
			memcpy(res + 12 + (i * sizeof(uint32_t)), (const unsigned char * const)&u32, sizeof(uint32_t));
		} else bzero(res + 12 + (i * sizeof(uint32_t)), sizeof(uint32_t));
	}

	return 12 + (AEM_USERCOUNT * sizeof(uint32_t));
}

int32_t api_account_delete(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	const uint16_t del_uid = *(const uint16_t * const)reqData;
	if (del_uid == 0) return api_response_status(res, AEM_API_ERR_ACCOUNT_FORBIDMASTER);
	if (del_uid >= AEM_USERCOUNT) return api_response_status(res, AEM_API_ERR_PARAM);
	if (user[api_uid]->level != AEM_USERLEVEL_MAX && api_uid != del_uid) return api_response_status(res, AEM_API_ERR_LEVEL);
	if (user[del_uid] == NULL) return api_response_status(res, AEM_API_ERR_ACCOUNT_NOTEXIST);

	sodium_memzero(user[del_uid], sizeof(struct aem_user));
	user[del_uid] = NULL;
	saveUser();

	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, AEM_ACC_STORAGE_DELETE, reqData, sizeof(uint16_t), NULL, 0);
	return api_response_status(res, (icRet == AEM_INTCOM_RESPONSE_OK) ? AEM_API_STATUS_OK : AEM_API_ERR_ACCOUNT_DELETE_NOSTORAGE);
}

int32_t api_account_permit(unsigned char * const res) {
	if (user[api_uid]->level != AEM_USERLEVEL_MAX) return api_response_status(res, AEM_API_ERR_LEVEL);

	aem_kdf_sub(res, crypto_aead_aegis256_KEYBYTES, user[api_uid]->lastBinTs, key_srk);
	return crypto_aead_aegis256_KEYBYTES;
}

int32_t api_account_update(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	const uint16_t upd_uid = *(const uint16_t * const)reqData;
	const uint8_t new_lvl = reqData[2];
	if (upd_uid == 0) return api_response_status(res, AEM_API_ERR_ACCOUNT_FORBIDMASTER);
	if (upd_uid >= AEM_USERCOUNT) return api_response_status(res, AEM_API_ERR_PARAM);
	if (user[api_uid]->level != AEM_USERLEVEL_MAX && (api_uid != upd_uid || new_lvl > user[api_uid]->level)) return api_response_status(res, AEM_API_ERR_LEVEL);
	if (user[upd_uid] == NULL) return api_response_status(res, AEM_API_ERR_ACCOUNT_NOTEXIST);

	user[upd_uid]->level = new_lvl;
	saveUser();
	return api_response_status(res, AEM_API_STATUS_OK);
}

int32_t api_address_create(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	const bool isShield = sodium_is_zero(reqData, 8);
	if (user[api_uid]->addrCount >= AEM_ADDRESSES_PER_USER) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_ATLIMIT);

	unsigned char addr32[10];
	uint64_t hash = 0;
	if (isShield) {
		if (numAddresses(api_uid, true) >= limits[user[api_uid]->level][AEM_LIMIT_SHD]) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_ATLIMIT);

		randombytes_buf(addr32, 10);
		addr32[0] |= 128;

		hash = addressToHash(addr32);
		if (hash == 0) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_INUSE);
	} else { // Normal
		if (numAddresses(api_uid, false) >= limits[user[api_uid]->level][AEM_LIMIT_NRM]) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_ATLIMIT);

		memcpy((unsigned char*)&hash, reqData, 8);

		if (user[api_uid]->level != AEM_USERLEVEL_MAX) {
			// Not admin, check if hash is forbidden
			for (int i = 0; i < AEM_ADDRHASH_ADMIN_COUNT; i++) {
				if (hash == AEM_ADDRHASH_ADMIN[i]) {
					hash = 0;
					break;
				}
			}
		}

		if (hash == 0 || hash == AEM_ADDRHASH_SYSTEM) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_INUSE);
	}

	if (hashToUid(hash, isShield, NULL) != UINT16_MAX) return api_response_status(res, AEM_API_ERR_ADDRESS_CREATE_INUSE);

	user[api_uid]->addrHash[user[api_uid]->addrCount] = hash;
	user[api_uid]->addrFlag[user[api_uid]->addrCount] = isShield? (AEM_ADDR_FLAGS_DEFAULT | AEM_ADDR_FLAG_SHIELD) : AEM_ADDR_FLAGS_DEFAULT;
	user[api_uid]->addrCount++;

	saveUser();

	if (!isShield) return api_response_status(res, AEM_API_STATUS_OK);

	// Shield address - send hash and address
	memcpy(res, (unsigned char*)&hash, 8);
	memcpy(res + 8, addr32, 10);
	return 18;
}

int32_t api_address_delete(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	int delNum = -1;
	for (int i = 0; i < user[api_uid]->addrCount; i++) {
		if (memeq(reqData, (unsigned char*)&user[api_uid]->addrHash[i], sizeof(uint64_t))) {
			delNum = i;
			break;
		}
	}

	if (delNum < 0) return api_response_status(res, AEM_API_ERR_ACCOUNT_NOTEXIST);

	if (delNum < (user[api_uid]->addrCount - 1)) {
		for (int i = delNum; i < user[api_uid]->addrCount - 1; i++) {
			user[api_uid]->addrHash[i] = user[api_uid]->addrHash[i + 1];
			user[api_uid]->addrFlag[i] = user[api_uid]->addrFlag[i + 1];
		}
	}

	user[api_uid]->addrCount--;
	saveUser();
	return api_response_status(res, AEM_API_STATUS_OK);
}

int32_t api_address_update(unsigned char * const res, const unsigned char * const data, const size_t lenData) {
	if (lenData != AEM_ADDRESSES_PER_USER) return AEM_INTCOM_RESPONSE_USAGE;

	for (int i = 0; i < AEM_ADDRESSES_PER_USER; i++) {
		user[api_uid]->addrFlag[i] = (user[api_uid]->addrFlag[i] & AEM_ADDR_FLAG_SHIELD) | (data[i] & ~AEM_ADDR_FLAG_SHIELD);
	}

	saveUser();
	return api_response_status(res, AEM_API_STATUS_OK);
}

int32_t api_message_browse(unsigned char * const res, unsigned char flags) {
	if ((flags & AEM_API_MESSAGE_BROWSE_FLAG_UINFO) == 0) return 0; // User data not requested, nothing to do

	// User data requested, add it to the response
	res[0] = user[api_uid]->level | (user[api_uid]->addrCount << 2);
	memcpy(res + 1, limits[user[api_uid]->level], 3);

	for (int i = 0; i < user[api_uid]->addrCount; i++) {
		memcpy(res + (i * 9) + 4, (unsigned char*)&user[api_uid]->addrHash[i], sizeof(uint64_t));
		res[(i * 9) + 12] = user[api_uid]->addrFlag[i];
	}

	memcpy(res + 4 + (user[api_uid]->addrCount * 9), user[api_uid]->private, AEM_LEN_PRIVATE);
	memcpy(res + 4 + (user[api_uid]->addrCount * 9) + AEM_LEN_PRIVATE, saltNormal, AEM_SALTNORMAL_LEN);
#ifdef AEM_ADDRESS_NOPWHASH
	bzero(res + 4 + (user[api_uid]->addrCount * 9) + AEM_LEN_PRIVATE + AEM_SALTNORMAL_LEN, 5);
#else
	const uint32_t mlim = AEM_ADDRESS_ARGON2_MEMLIMIT;
	res[4 + (user[api_uid]->addrCount * 9) + AEM_LEN_PRIVATE + AEM_SALTNORMAL_LEN] = AEM_ADDRESS_ARGON2_OPSLIMIT;
	memcpy(res + 5 + (user[api_uid]->addrCount * 9) + AEM_LEN_PRIVATE + AEM_SALTNORMAL_LEN, (const unsigned char*)&mlim, sizeof(uint32_t));
#endif

	return 5 + (user[api_uid]->addrCount * 9) + AEM_LEN_PRIVATE + crypto_pwhash_SALTBYTES + sizeof(uint32_t);
}

int32_t api_setting_limits(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]) {
	memcpy(limits, reqData, 12);
	saveSettings();
	return api_response_status(res, AEM_API_STATUS_OK);
}

// API: POST (Continue)
int32_t api_account_keyset(unsigned char * const res, const unsigned char * const data, const size_t lenData) {
	if (lenData != AEM_USK_KEYLEN + AEM_PWK_KEYLEN) return api_response_status(res, AEM_API_ERR_PARAM);
	memcpy(user[api_uid]->usk, data, AEM_USK_KEYLEN);
	memcpy(user[api_uid]->pwk, data + AEM_USK_KEYLEN, AEM_PWK_KEYLEN);

	struct evpKeys ek;
	bzero(&ek, sizeof(struct evpKeys));
	memcpy(ek.pwk, user[api_uid]->pwk, AEM_PWK_KEYLEN);

	unsigned char icMsg[sizeof(uint16_t) + sizeof(struct evpKeys)];
	memcpy(icMsg, (const unsigned char * const)&api_uid, sizeof(uint16_t));
	memcpy(icMsg + sizeof(uint16_t), &ek, sizeof(struct evpKeys));
	const int32_t icRet = intcom(AEM_INTCOM_SERVER_STO, AEM_ACC_STORAGE_CREATE, icMsg, sizeof(uint16_t) + sizeof(struct evpKeys), NULL, 0);
	if (icRet != AEM_INTCOM_RESPONSE_OK) return api_response_status(res, AEM_API_ERR_INTERNAL);

	saveUser();
	return api_response_status(res, AEM_API_STATUS_OK);
}

int32_t api_private_update(unsigned char * const res, unsigned char * const data, const size_t lenData) {
	if (
	   lenData != (crypto_stream_chacha20_ietf_NONCEBYTES + crypto_stream_chacha20_ietf_KEYBYTES + AEM_LEN_PRIVATE)
	|| sodium_is_zero(data + crypto_stream_chacha20_ietf_NONCEBYTES, crypto_stream_chacha20_ietf_KEYBYTES)
	) return api_response_status(res, AEM_API_ERR_PARAM);

	crypto_stream_chacha20_ietf_xor(
		data + crypto_stream_chacha20_ietf_NONCEBYTES + crypto_stream_chacha20_ietf_KEYBYTES + 4,
		data + crypto_stream_chacha20_ietf_NONCEBYTES + crypto_stream_chacha20_ietf_KEYBYTES + 4,
		AEM_LEN_PRIVATE - 4, data, data + crypto_stream_chacha20_ietf_NONCEBYTES);

	memcpy(user[api_uid]->private, data + crypto_stream_chacha20_ietf_NONCEBYTES + crypto_stream_chacha20_ietf_KEYBYTES, AEM_LEN_PRIVATE);
	saveUser();
	return api_response_status(res, AEM_API_STATUS_OK);
}

// API: POST (Status)
int32_t api_message_create(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN], const int flags) {
	if (flags == AEM_API_MESSAGE_CREATE_FLAG_EMAIL) {
		if (user[api_uid]->level < AEM_MINLEVEL_SENDEMAIL) return api_response_status(res, AEM_API_ERR_LEVEL);

		const unsigned char * const addrEnd = memchr(reqData, '\0', AEM_API_REQ_DATA_LEN);
		if (addrEnd == NULL) return api_response_status(res, AEM_API_ERR_PARAM);
		unsigned char a32[10];
		addr32_store(a32, reqData, addrEnd - reqData);

		// Verify user owns their sending address
		if (api_uid != hashToUid(addressToHash(a32), (a32[0] & 128) != 0, NULL))
			return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_EXT_HDR_ADFR);

		memcpy(res, (unsigned char*)&api_uid, sizeof(uint16_t));
		if (user[api_uid]->level == AEM_USERLEVEL_MAX) {
			res[1] |= 128;
			memcpy(res + sizeof(uint16_t), rsaAdminKey, lenRsaAdminKey);
			return sizeof(uint16_t) + lenRsaAdminKey;
		} else {
			memcpy(res + sizeof(uint16_t), rsaUsersKey, lenRsaUsersKey);
			return sizeof(uint16_t) + lenRsaUsersKey;
		}
	} else { // Internal mail
		// Verify user owns their sending address
		if (api_uid != hashToUid(addressToHash(reqData), (reqData[0] & 128) != 0, NULL))
			return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_INT_NOT_OWN);

		if (flags == AEM_API_MESSAGE_CREATE_FLAG_PUB) {
			if (user[api_uid]->level != AEM_USERLEVEL_MAX) return api_response_status(res, AEM_API_ERR_LEVEL);

			// Public: return list of users that exist
			size_t s = 0;
			for (unsigned int i = 0; i < 4095; i++) {
				if (user[i] == NULL) continue;
				res[s] = i & 255;
				res[s + 1] = i >> 8;
				s += 2;
			}

			return s;
		} else {
			// Individual: get recipient address
			const uint64_t hash = addressToHash(reqData + 10);
			if (hash == 0) return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_INT_TO_INVALID);

			unsigned char addrFlags = 0;
			const uint16_t uid = hashToUid(hash, (reqData[10] & 128) != 0, &addrFlags);
			if (uid == UINT16_MAX) return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_INT_TO_NOTREG);
			if (uid == api_uid) return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_INT_TO_SELF);
			if ((addrFlags & AEM_ADDR_FLAG_ACCINT) == 0) return api_response_status(res, AEM_API_ERR_MESSAGE_CREATE_INT_TO_DECLINE);

			memcpy(res, (const unsigned char*)&uid, sizeof(uint16_t));
			return 2;
		}
	}
}

//
static void uak_derive(unsigned char * const out, const int lenOut, const uint64_t binTs, const uint16_t uid, const bool post, const unsigned long long type) {
	aem_kdf_sub(out, lenOut, binTs | (post? (1LLU << 47) : 0) | (type << 45), user[uid]->uak);
}

int32_t api_auth(unsigned char * const res, union aem_req * const req, const bool post) {
	// Find which (if any) user has a key that authenticates this request
	bool found = false;
	api_uid = 0;
	for (;api_uid < AEM_USERCOUNT; api_uid++) {
		if (user[api_uid] == NULL) continue;

		unsigned char req_key_auth[crypto_onetimeauth_KEYBYTES];
		uak_derive(req_key_auth, crypto_onetimeauth_KEYBYTES, req->n.binTs, api_uid, post, AEM_UAK_TYPE_URL_AUTH);
		if (crypto_onetimeauth_verify(req->c.mac, (unsigned char*)req + 5, AEM_API_REQ_LEN - crypto_onetimeauth_BYTES - 5, req_key_auth) == 0) {
			if (req->n.binTs <= user[api_uid]->lastBinTs) return AEM_INTCOM_RESPONSE_AUTH_REPLAY; // This request isn't newer than the last recorded one - suspected replay attack
			if (llabs((int64_t)req->n.binTs - (int64_t)getBinTs()) > AEM_API_TIMEDIFF) return AEM_INTCOM_RESPONSE_AUTH_TIMEDIFF;

			found = true;
			break;
		}
	}

	if (!found) return AEM_INTCOM_RESPONSE_AUTH_NOTEXIST;
	user[api_uid]->lastBinTs = req->n.binTs;

	// Decrypt
	unsigned char req_key_data[1 + AEM_API_REQ_DATA_LEN];
	uak_derive(req_key_data, 1 + AEM_API_REQ_DATA_LEN, req->n.binTs, api_uid, post, AEM_UAK_TYPE_URL_DATA);

	req->n.cmd ^= (req_key_data[0] & 60) >> 2;
	if (sodium_is_zero(user[api_uid]->pwk, AEM_PWK_KEYLEN) && req->n.cmd != AEM_API_ACCOUNT_KEYSET) return AEM_INTCOM_RESPONSE_AUTH_KEYSET;

	if ( // Admin-only APIs
	(  (!post && req->n.cmd == AEM_API_ACCOUNT_BROWSE)
	|| (!post && req->n.cmd == AEM_API_ACCOUNT_PERMIT)
	|| (!post && req->n.cmd == AEM_API_ACCOUNT_UPDATE)
	|| (!post && req->n.cmd == AEM_API_SETTING_LIMITS)
	|| ( post && req->n.cmd == AEM_API_MESSAGE_SENDER)
	) && (user[api_uid]->level != AEM_USERLEVEL_MAX))
		return AEM_INTCOM_RESPONSE_AUTH_LEVEL;

	req->n.flags ^= (req_key_data[0] & 192) >> 6;

	for (int i = 0; i < AEM_API_REQ_DATA_LEN; i++) {
		req->c.data[i] ^= req_key_data[1 + i];
	}

	// Copy data to the base response
	res[0] = req->n.cmd;
	res[1] = req->n.flags;
	memcpy(res + 2, &api_uid, 2);
	memcpy(res + 4, req->c.data, AEM_API_REQ_DATA_LEN);
	uak_derive(res + 4 + AEM_API_REQ_DATA_LEN, AEM_API_BODY_KEYSIZE, req->n.binTs, api_uid, post, AEM_UAK_TYPE_BODY_REQ);
	uak_derive(res + 4 + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE, AEM_API_BODY_KEYSIZE, req->n.binTs, api_uid, post, AEM_UAK_TYPE_BODY_RES);

	return AEM_INTCOM_RESPONSE_OK;
}

// To allow Continue request, but nothing older
void decreaseLastBinTs(void) {
	user[api_uid]->lastBinTs--;
}

// MTA
int32_t mta_getUid(const unsigned char * const addr32, unsigned char **res) {
	const bool isShield = ((addr32[0] & 128) != 0);

	const uint64_t hash = addressToHash(addr32);
	if (hash == 0) return AEM_INTCOM_RESPONSE_ERR;

	unsigned char flags = 0;
	const uint16_t uid = hashToUid(hash, isShield, &flags);
	if (uid == UINT16_MAX || (flags & AEM_ADDR_FLAG_ACCEXT) == 0) {
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
	(*res)[sizeof(uint16_t)] = flags & (AEM_ADDR_FLAG_ALLVER | AEM_ADDR_FLAG_ATTACH | AEM_ADDR_FLAG_SECURE | AEM_ADDR_FLAG_ORIGIN);

	return 3;
}

// Reg
int32_t reg_register(const unsigned char * const req, unsigned char **res) {
	unsigned char nonce[crypto_aead_aegis256_NPUBBYTES];
	memcpy(nonce, req, 9);
	memset(nonce + 9, 0x00, 23);

	const uint64_t bts = ((uint64_t)req[0]) | ((uint64_t)req[1] << 8) | ((uint64_t)req[2] << 16) | ((uint64_t)req[3] << 24) | ((uint64_t)req[4] << 32) | ((uint64_t)(req[5] & 3) << 40);
	unsigned char urk[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_sub(urk, crypto_aead_aegis256_KEYBYTES, bts, key_srk);

	unsigned char new_uak[AEM_KDF_SUB_KEYLEN];
	if (crypto_aead_aegis256_decrypt(new_uak, NULL, NULL, req + 9, AEM_KDF_SUB_KEYLEN + crypto_aead_aegis256_ABYTES, NULL, 0, nonce, urk) == -1) {
		syslog(LOG_WARNING, "Reg: Failed decrypt");
		return AEM_INTCOM_RESPONSE_ERR;
	}

	uint16_t new_uid;
	aem_kdf_sub((unsigned char*)&new_uid, 2, AEM_KDF_KEYID_UAK_UID, new_uak);
	new_uid &= 4095;

	*res = malloc(1 + crypto_aead_aegis256_ABYTES);
	if (*res == NULL) {syslog(LOG_ERR, "Failed malloc"); return AEM_INTCOM_RESPONSE_ERR;}

	unsigned char regStatus = 2;
	if (user[new_uid] == NULL) {
		user[new_uid] = malloc(sizeof(struct aem_user));
		bzero(user[new_uid], sizeof(struct aem_user));
		user[new_uid]->lastBinTs = getBinTs();
		memcpy(user[new_uid]->uak, new_uak, AEM_KDF_SUB_KEYLEN);
		saveUser();
		regStatus = 1;
	} else {
		regStatus = 3;
	}

	memset(nonce + 9, 0xFF, 23);
	crypto_aead_aegis256_encrypt(*res, NULL, &regStatus, 1, NULL, 0, NULL, nonce, urk);
	return 1 + crypto_aead_aegis256_ABYTES;
}

// Storage
int32_t sto_uid2keys(const uint16_t uid, unsigned char **res) {
	if (user[uid] == NULL) return AEM_INTCOM_RESPONSE_NOTEXIST;

	*res = malloc(sizeof(struct evpKeys));
	if (*res == NULL) {syslog(LOG_ERR, "Failed malloc"); return AEM_INTCOM_RESPONSE_ERR;}

	((struct evpKeys*)*res)->security = false;
	memcpy(((struct evpKeys*)*res)->pwk, user[uid]->pwk, AEM_PWK_KEYLEN);
	memcpy(((struct evpKeys*)*res)->psk, user[uid]->psk, AEM_PSK_KEYLEN);
	memcpy(((struct evpKeys*)*res)->pqk, user[uid]->pqk, AEM_PQK_KEYLEN);
	memcpy(((struct evpKeys*)*res)->usk, user[uid]->usk, AEM_USK_KEYLEN);

	return sizeof(struct evpKeys);
}

// Setup
void setRsaKeys(const unsigned char * const keyAdmin, const size_t lenKeyAdmin, const unsigned char * const keyUsers, const size_t lenKeyUsers) {
	memcpy(rsaAdminKey, keyAdmin, lenKeyAdmin);
	memcpy(rsaUsersKey, keyUsers, lenKeyUsers);
	lenRsaAdminKey = lenKeyAdmin;
	lenRsaUsersKey = lenKeyUsers;
}

void ioFree(void) {
	sodium_memzero(accountKey, crypto_aead_aegis256_KEYBYTES);
	sodium_memzero(saltShield, crypto_shorthash_KEYBYTES);

	for (int i = 0; i < AEM_USERCOUNT; i++) {
		if (user[i] == NULL) continue;
		sodium_memzero(user[i], sizeof(struct aem_user));
		free(user[i]);
	}

	sodium_memzero(rsaAdminKey, lenRsaAdminKey);
	sodium_memzero(rsaUsersKey, lenRsaUsersKey);
}

int ioSetup(const unsigned char baseKey[AEM_KDF_SUB_KEYLEN]) {
	aem_kdf_sub(accountKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_ACC_ACC, baseKey);
	aem_kdf_sub(saltNormal, AEM_SALTNORMAL_LEN,            AEM_KDF_KEYID_ACC_NRM, baseKey);
	aem_kdf_sub(saltShield, crypto_shorthash_KEYBYTES,     AEM_KDF_KEYID_ACC_SHD, baseKey);
	aem_kdf_sub(key_srk,    AEM_KDF_SUB_KEYLEN,            AEM_KDF_KEYID_ACC_REG, baseKey);

	if (loadUser() != 0) return -1;
	loadSettings(); // Ignore errors
//	bzero((unsigned char*)fakeFlag_expire, 4 * AEM_FAKEFLAGS_HTSIZE);

//	if (intcom(AEM_INTCOM_SERVER_STO, AEM_ACC_STORAGE_LIMITS, (unsigned char[4]){limits[0][0], limits[1][0], limits[2][0], limits[3][0]}, 4, NULL, 0) != AEM_INTCOM_RESPONSE_OK) {
//		syslog(LOG_ERR, "ioSetup: intcom failed");
//		return -1;
//	}

	return 0;
}
