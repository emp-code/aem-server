#include <string.h>

#include <sodium.h>

#include "Signature.h"

static unsigned char ssk[AEM_SSK_KEYLEN]; // Server Signature Key

void setSigKey(const unsigned char * const newKey) {
	memcpy(ssk, newKey, AEM_SSK_KEYLEN);
}

void delSigKey(void) {
	sodium_memzero(ssk, AEM_SSK_KEYLEN);
}

void aem_sign_message(unsigned char * const msg, const size_t lenMsg, const unsigned char usk[AEM_USK_KEYLEN]) {
	if (lenMsg <= AEM_MSG_HDR_SZ) return;

	unsigned char uHash[56];
	crypto_generichash((unsigned char*)uHash, 56, msg + 27, lenMsg - 27, usk, AEM_USK_KEYLEN); // +27: skip the beginning of the 222-bit signature (remaining signature bits are zero)
	unsigned char sHash[28];
	crypto_generichash((unsigned char*)sHash, 28, uHash,    56,          ssk, AEM_SSK_KEYLEN);

	// Store signature in header, preserving the type bits
	memcpy(msg, sHash, 27);
	msg[27] = (sHash[27] & 252) | (msg[27] & 3); // set 6 signature bits, preserve 2 type bits
}

bool aem_sig_verify(const unsigned char uHash[56], const unsigned char sHash_test[28]) {
	unsigned char sHash_real[28];
	crypto_generichash((unsigned char*)sHash_real, 28, uHash, 56, ssk, AEM_SSK_KEYLEN);
	sHash_real[27] &= 252;
	return (sodium_memcmp(sHash_real, sHash_test, 28) == 0);
}
