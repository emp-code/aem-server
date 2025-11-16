#include <strings.h>

#include <sodium.h>

#include "AEM_KDF.h"

// Use the 368-bit Server Master Key (SMK) with an 8-bit nonce to generate up to 16 KiB
__attribute__((nonnull))
void aem_kdf_smk(unsigned char * const out, const size_t lenOut, const uint8_t n, const unsigned char smk[AEM_KDF_SMK_KEYLEN]) {
	bzero(out, lenOut);
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut,
	/* Nonce */ smk + 32,
	/* Counter */ ((uint32_t)smk[44] << 24) | (smk[45] << 16) | (n << 8),
	smk);
}

// Use the 338-bit UAK to generate up to 64 bytes
__attribute__((nonnull))
void aem_kdf_uak(unsigned char * const out, const size_t lenOut, const uint64_t binTs, const bool post, const uint8_t type, const unsigned char key[AEM_KDF_UAK_KEYLEN]) {
	bzero(out, lenOut);
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut,
	/* Nonce */ (const uint8_t[]){(binTs >> 32) & 255, ((binTs >> 40) & 3) | (post? AEM_UAK_POST : 0) | type | (key[42] & 12), key[41], key[40], key[39], key[38], key[37], key[36], key[35], key[34], key[33], key[32]},
	/* Counter */ binTs & UINT32_MAX,
	key);
}

// Get UserID from UAK
__attribute__((warn_unused_result))
uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_UAK_KEYLEN]) {
	uint16_t uid;
	aem_kdf_uak((unsigned char*)&uid, sizeof(uint16_t), 0, false, 0, uak);
	return uid & 4095;
}

// Use the 320-bit subkey with a 56-bit nonce to generate up to 16 KiB
__attribute__((nonnull))
void aem_kdf_sub(unsigned char * const out, const size_t lenOut, const uint64_t n, const unsigned char key[AEM_KDF_SUB_KEYLEN]) {
	bzero(out, lenOut);
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut,
	/* Nonce */ (const uint8_t[]){key[32], key[33], key[34], key[35], key[36], key[37], key[38], key[39], ((const uint8_t*)&n)[0], ((const uint8_t*)&n)[1], ((const uint8_t*)&n)[2], ((const uint8_t*)&n)[3]},
	/* Counter */ (((const uint8_t*)&n)[4] << 8) | (((const uint8_t*)&n)[5] << 16) | ((unsigned int)(((const uint8_t*)&n)[6]) << 24),
	key);
}

#ifdef AEM_KDF_UMK
// Use the 360-bit User Master Key (UMK) with a 16-bit nonce to generate up to 16 KiB
__attribute__((nonnull))
void aem_kdf_umk(unsigned char * const out, const size_t lenOut, const uint16_t n, const unsigned char umk[AEM_KDF_UMK_KEYLEN]) {
	bzero(out, lenOut);
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut,
	/* Nonce */ umk + 32,
	/* Counter */ (umk[44] << 24) | (n << 8),
	umk);
}
#endif
