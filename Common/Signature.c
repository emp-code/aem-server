#include <string.h>

#include <sodium.h>

#include "../Global.h"
#include "memeq.h"

#include "Signature.h"

static unsigned char sigKey[AEM_SIG_KEYLEN];

void setSigKey(const unsigned char * const newKey) {
	memcpy(sigKey, newKey, AEM_SIG_KEYLEN);
}

void delSigKey(void) {
	sodium_memzero(sigKey, AEM_SIG_KEYLEN);
}

void aem_sign_message(unsigned char * const msg, const size_t lenMsg) {
	unsigned char baseHash[48];
	crypto_generichash(baseHash, 48, msg + X25519_PKBYTES + AEM_MSG_SIG_LEN, lenMsg - X25519_PKBYTES - AEM_MSG_SIG_LEN, NULL, 0);
	crypto_generichash(msg + X25519_PKBYTES, AEM_MSG_SIG_LEN, baseHash, 48, sigKey, AEM_SIG_KEYLEN);
}

bool aem_sig_verify(const unsigned char * const baseHash, const unsigned char * const sig) {
	unsigned char sig2[AEM_MSG_SIG_LEN];
	crypto_generichash(sig2, AEM_MSG_SIG_LEN, baseHash, 48, sigKey, AEM_SIG_KEYLEN);

	const bool ret = memeq(sig, sig2, AEM_MSG_SIG_LEN);
	sodium_memzero(sig2, AEM_MSG_SIG_LEN);
	return ret;
}
