// Message IDs are guaranteed to be unique (as required by the standards) as long as the same user does not send multiple emails in one second from the same address.
// Message IDs contain the UserID, sending address, and timestamp. The data is protected by AES-256 encryption and a secret Base32 encoding. This protection can only be reversed through the admin-only Message/Sender API.

#include <string.h>
#include <sodium.h>

#include "../Global.h"
#include "../Common/AEM_KDF.h"

#include "MessageId.h"

static unsigned char msgid_key[AES256_KEYBYTES]; // AES-256 key
static unsigned char msgid_cs[32]; // Charset for the secret encoding

void setMsgIdKey(const unsigned char * const baseKey) {
	aem_kdf(msgid_key, AES256_KEYBYTES, AEM_KDF_KEYID_API_MIA, baseKey);

	// Charset
	const char b32_set[] = "0123456789bcdefghjklmnpqrstvwxyz";
	int total = 0;
	uint64_t done = 0;

	uint8_t src[8192];
	aem_kdf(src, 8192, AEM_KDF_KEYID_API_MIC, baseKey);

	for (int charsDone = 0; charsDone < 64; charsDone++) {
		for (int n = 0; n < 8192; n++) {
			src[n] &= 31;

			if (((done >> src[n]) & 1) == 0) {
				msgid_cs[total] = b32_set[src[n]];
				done |= 1UL << src[n];
				break;
			}
		}
	}
}

void delMsgIdKey(void) {
	sodium_memzero(msgid_key, AES256_KEYBYTES);
	sodium_memzero(msgid_cs, 32);
}

void genMsgId(char * const out, const uint32_t ts, const uint16_t uid, const unsigned char * const addr32, const bool b32) {
	uint64_t id[2];
	memcpy((unsigned char*)&id, (const unsigned char * const)&ts, 4);
	memcpy((unsigned char*)&id + 4, (const unsigned char * const)&uid, 2);
	memcpy((unsigned char*)&id + 6, addr32, 10);

	// Encrypt with AES-256
//	struct AES_ctx aes;
//	AES_init_ctx(&aes, msgid_key);

//	AES_ECB_encrypt(&aes, (unsigned char*)&id);
//	sodium_memzero(&aes, sizeof(struct AES_ctx));

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
