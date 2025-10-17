#include <stdint.h>
#include <syslog.h>

#include "../Global.h"
#include "memeq.h"

#include "AddrToHash.h"

static unsigned char saltNrm[AEM_SALTNORMAL_LEN];
static unsigned char saltShd[crypto_shorthash_KEYBYTES];

void addressToHash_salt(const unsigned char baseKey[AEM_KDF_SUB_KEYLEN]) {
	aem_kdf_sub(saltNrm, AEM_SALTNORMAL_LEN,        AEM_KDF_KEYID_ACC_NRM, baseKey);
	aem_kdf_sub(saltShd, crypto_shorthash_KEYBYTES, AEM_KDF_KEYID_ACC_SHD, baseKey);
}

void addressToHash_clear(void) {
	sodium_memzero(saltNrm, AEM_SALTNORMAL_LEN);
	sodium_memzero(saltShd, crypto_shorthash_KEYBYTES);
}

__attribute__((warn_unused_result))
uint64_t addressToHash(const unsigned char * const addr32) {
	if (addr32 == NULL) return 0;

	if ((addr32[0] & 128) != 0) {
		// Shield
		if (memeq(addr32 + 2, AEM_ADDR32_ADMIN, 8)) return 0; // Forbid addresses ending with 'administrator'
		uint64_t hash;
		crypto_shorthash((unsigned char*)&hash, addr32, AEM_ADDR32_BINLEN, saltShd);
		return hash;
	}

	// Normal
	if (memeq(addr32, AEM_ADDR32_SYSTEM, AEM_ADDR32_BINLEN)) return 0; // Forbid 'system'
	if (addr32[0] >> 3 == 0) return 0; // Forbid zero length

#ifdef AEM_ADDRESS_NOPWHASH
	uint64_t hash;
	crypto_shorthash((unsigned char*)&hash, addr32, AEM_ADDR32_BINLEN, saltNrm);
	return hash;
#else
	uint64_t halves[2];
	if (crypto_pwhash((unsigned char*)halves, sizeof(uint64_t) * 2, (const char*)addr32, AEM_ADDR32_BINLEN, saltNrm, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) {
		syslog(LOG_ERR, "Failed hashing address");
		return 0;
	}
	return halves[0] ^ halves[1];
#endif
}
