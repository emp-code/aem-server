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

	unsigned char uHash[54];
	crypto_generichash((unsigned char*)uHash, 54, msg + 26, lenMsg - 26, usk, AEM_USK_KEYLEN); // Skip 26*8=208 of the 212 signature bits (remaining four bits are zero)
	unsigned char sHash[27];
	crypto_generichash((unsigned char*)sHash, 27, uHash,    56,          ssk, AEM_SSK_KEYLEN);

	memcpy(msg, sHash, 26);
	msg[26] = (sHash[26] & 15) | (msg[26] & 240); // Copy the remaining four Signature bits, but preserve the two Type bits and two BinTs bits
}

bool aem_sig_verify(const unsigned char uHash[54], const unsigned char sHash_test[27]) {
	unsigned char sHash_real[27];
	crypto_generichash((unsigned char*)sHash_real, 27, uHash, 54, ssk, AEM_SSK_KEYLEN);
	sHash_real[26] &= 15;
	return (sodium_memcmp(sHash_real, sHash_test, 27) == 0);
}
