/*
	Message IDs are unique (as required by the standards) as long as the same user does not send multiple emails in one second.

	The message ID can be used to trace which user sent the email, but only by admins, and only once given the message-ID and timestamp by the receiver.
	Because it's a hash, it can only be tested against existing users. No other information can be gotten from it.
	The encryption may not be strictly necessary, but is used for additional security.
	A large (384-bit) hash is used to avoid false positives.

The full UPK and timestamp are used to calculate the hash:
	The Blake2 key derivation uses the first 8 bytes of UPK
	The AES256 key derivation uses the next 4 bytes of UPK and the 4-byte ts
	The hash uses the final 20 bytes (8+4+20=32)
*/

#include <string.h>
#include <sodium.h>

#include "../Common/aes.h"

#include "MessageId.h"

#include <syslog.h>

static unsigned char msgid_derivkey[crypto_kdf_KEYBYTES];

void setMsgIdKey(const unsigned char * const src) {
	crypto_kdf_derive_from_key(msgid_derivkey, crypto_kdf_KEYBYTES, 0, "AEM-MIDr", src);
}

void genMsgId(char * const out, const uint32_t ts, const unsigned char * const upk, const bool b64) {
	// Generate the Blake2-384 hash
	unsigned char hashSrc[20];
	memcpy(hashSrc, upk + 12, 20);

	unsigned char hashKey[crypto_generichash_KEYBYTES];
	crypto_kdf_derive_from_key(hashKey, crypto_generichash_KEYBYTES, *((uint64_t*)upk), "AEM-MIHs", msgid_derivkey);

	unsigned char hash[48]; // 384-bit
	crypto_generichash(hash, 48, hashSrc, 20, hashKey, crypto_generichash_KEYBYTES);

	sodium_memzero(hashSrc, 20);
	sodium_memzero(hashKey, crypto_generichash_KEYBYTES);

	// Encrypt the hash with AES256-ECB
	uint64_t aesKey_nr;
	memcpy((unsigned char*)&aesKey_nr, upk + 8, 4);
	memcpy((unsigned char*)&aesKey_nr + 4, (unsigned char*)&ts, 4);

	unsigned char aesKey[32];
	crypto_kdf_derive_from_key(aesKey, 32, aesKey_nr, "AEM-MIEn", msgid_derivkey);
	sodium_memzero(&aesKey_nr, 4);

	struct AES_ctx aes;
	AES_init_ctx(&aes, aesKey);
	AES_ECB_encrypt(&aes, hash);
	AES_ECB_encrypt(&aes, hash + 16);
	AES_ECB_encrypt(&aes, hash + 32);
	sodium_memzero(&aes, sizeof(struct AES_ctx));

	if (b64) {
		sodium_bin2base64(out, 65, hash, 48, sodium_base64_VARIANT_URLSAFE);
	} else {
		memcpy(out, hash, 48);
	}

	sodium_memzero(hash, 48);
}
