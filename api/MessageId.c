// Message IDs are guaranteed to be unique (as required by the standards) as long as the same user does not send multiple emails in one second from the same address.
// Message IDs contain the UserID, sending address, and timestamp. The data is protected by a secret Base32 encoding and AES-256 encryption. This protection can only be reversed through the admin-only Message/Sender API.

#include <string.h>
#include <syslog.h>
#include <time.h>

#include <sodium.h>
#include <wolfssl/options.h>
#define WOLFSSL_AES_DIRECT
#include <wolfssl/wolfcrypt/aes.h>

#include "../Global.h"
#include "../Common/AEM_KDF.h"
#include "Error.h"

#include "MessageId.h"

static unsigned char msgid_key[32]; // AES key
static unsigned char msgid_cs[32]; // Charset for the secret encoding

void setMsgIdKey(const unsigned char * const baseKey) {
	aem_kdf_sub(msgid_key, 32, AEM_KDF_KEYID_API_MIA, baseKey);

	const char b32_set[] = "0123456789bcdefghjklmnpqrstvwxyz";
	int total = 0;
	uint64_t done = 0;

	uint8_t src[8192];
	aem_kdf_sub(src, 8192, AEM_KDF_KEYID_API_MIC, baseKey);

	for (int i = 0; total < 32; i++) {
		src[i] &= 31;
		if (((done >> src[i]) & 1) == 0) {
			msgid_cs[total] = b32_set[src[i]];
			done |= 1LLU << src[i];
			total++;
		}
	}

	sodium_memzero(src, 8192);
}

void delMsgIdKey(void) {
	sodium_memzero(msgid_key, 32);
	sodium_memzero(msgid_cs, 32);
}

void genMsgId(char * const out, const uint32_t ts, const uint16_t uid, const unsigned char * const addr32, const bool b32) {
	// Create the raw base ID
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	const uint16_t uid_ts = (uid & 4095) | ((t.tv_nsec & 15) << 12);

	unsigned char raw_id[16];
	memcpy(raw_id,     (const unsigned char * const)&ts, 4);
	memcpy(raw_id + 4, (const unsigned char * const)&uid_ts, 2);
	memcpy(raw_id + 6, addr32, 10);

	// Encrypt with AES-256
	uint64_t id[2];
	Aes aes;
	wc_AesInit(&aes, NULL, INVALID_DEVID);
	if (wc_AesSetKey(&aes, msgid_key, 32, NULL, AES_ENCRYPTION) != 0 || wc_AesEncryptDirect(&aes, (unsigned char*)id, raw_id) != 0) {
		syslog(LOG_ERR, "Failed MsgId encrypt");
		randombytes_buf((unsigned char*)id, 16);
	}
	wc_AesFree(&aes);

	// Copy result
	if (b32) {
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 13; j++) {
				out[i * 13 + j] = msgid_cs[(id[i] >> (j * 5)) & 31];
			}
		}
	} else {
		memcpy(out, (unsigned char*)id, 16);
	}

	// Clean up
	sodium_memzero((unsigned char*)id, 16);
}

static int idVal(const unsigned char c) {
	const unsigned char * const x = memchr(msgid_cs, c, 32);
	return (x == NULL) ? -1 : x - msgid_cs;
}

int decryptMsgId(unsigned char * const out, const unsigned char * const src, const size_t lenSrc) {
	if (lenSrc != 26) {
		*out = AEM_API_ERR_INTERNAL;
		return 1;
	}

	uint64_t id[2] = {
	   (uint64_t)idVal(src[ 0]      )  | ((uint64_t)idVal(src[ 1]) <<  5) | ((uint64_t)idVal(src[ 2]) << 10) | ((uint64_t)idVal(src[ 3]) << 15) | ((uint64_t)idVal(src[ 4]) << 20) | ((uint64_t)idVal(src[ 5]) << 25)
	| ((uint64_t)idVal(src[ 6]) << 30) | ((uint64_t)idVal(src[ 7]) << 35) | ((uint64_t)idVal(src[ 8]) << 40) | ((uint64_t)idVal(src[ 9]) << 45) | ((uint64_t)idVal(src[10]) << 50) | ((uint64_t)idVal(src[11]) << 55)
	| (((uint64_t)idVal(src[12]) & 15) << 60)
	,
	   (uint64_t)idVal(src[13]       ) | ((uint64_t)idVal(src[14]) <<  5) | ((uint64_t)idVal(src[15]) << 10) | ((uint64_t)idVal(src[16]) << 15) | ((uint64_t)idVal(src[17]) << 20) | ((uint64_t)idVal(src[18]) << 25)
	| ((uint64_t)idVal(src[19]) << 30) | ((uint64_t)idVal(src[20]) << 35) | ((uint64_t)idVal(src[21]) << 40) | ((uint64_t)idVal(src[22]) << 45) | ((uint64_t)idVal(src[23]) << 50) | ((uint64_t)idVal(src[24]) << 55)
	| (((uint64_t)idVal(src[25]) & 15) << 60)
	};

	Aes aes;
	wc_AesInit(&aes, NULL, INVALID_DEVID);
	if (wc_AesSetKey(&aes, msgid_key, 32, NULL, AES_DECRYPTION) != 0 || wc_AesDecryptDirect(&aes, out, (unsigned char*)id) != 0) {
		syslog(LOG_ERR, "Failed MsgId decrypt");
		*out = AEM_API_ERR_INTERNAL;
		return 1;
	}

	return 16;
}
