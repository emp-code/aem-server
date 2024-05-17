#include <strings.h>

#include <sodium.h>

#include "AEM_KDF.h"

void aem_kdf_master(unsigned char * const out, const size_t lenOut, const uint8_t id, const unsigned char key[AEM_KDF_MASTER_KEYLEN]) {
	bzero(out, lenOut);
	const uint32_t counter = (id << 8) | (key[44] << 16) | ((uint32_t)key[45] << 24); // 0, id, key[44], key[45]
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut, key + 32, counter, key);
}

void aem_kdf_sub(unsigned char * const out, const size_t lenOut, const uint64_t n, const unsigned char key[AEM_KDF_SUB_KEYLEN]) {
	bzero(out, lenOut);
	const uint32_t counter = ((key[36] & 127) << 24) | ((key[36] & 128) << 16); // 0, 0, highest bit of key[36], 7 lower bits of key[36]; allows 512 MiB output, avoids the sign bit for compability
	const unsigned char nonce[] = {key[32], key[33], key[34], key[35], n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >> 24) & 255, (n >> 32) & 255, (n >> 40) & 255, (n >> 48) & 255, (n >> 56) & 255};
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut, nonce, counter, key);
}

uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_SUB_KEYLEN]) {
	uint16_t uid;
	aem_kdf_sub((unsigned char*)&uid, sizeof(uint16_t), AEM_KDF_KEYID_UAK_UID, uak);
	return uid & 4095;
}
