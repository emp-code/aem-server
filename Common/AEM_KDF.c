#include <sodium.h>

#include "AEM_KDF.h"

void aem_kdf(unsigned char * const out, const size_t lenOut, const uint64_t nonce, const unsigned char key[crypto_stream_chacha20_KEYBYTES]) {
	crypto_stream_chacha20(out, lenOut, (const unsigned char * const)&nonce, key);
}

void aem_kdf_xor(unsigned char * const target, const size_t lenTarget, const uint64_t nonce, const unsigned char key[crypto_stream_chacha20_KEYBYTES]) {
	crypto_stream_chacha20_xor(target, target, lenTarget, (const unsigned char * const)&nonce, key);
}

uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_KEYSIZE]) {
	uint16_t uid;
	aem_kdf((unsigned char*)&uid, 2, AEM_KDF_KEYID_UAK_UID, uak);
	return uid & 4095;
}
