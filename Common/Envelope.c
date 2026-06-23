#include <sys/param.h>
#include <syslog.h>

#include <sodium.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

#include "../Global.h"

#include "Envelope.h"

uint16_t getEnvelopeId(const unsigned char * const src) {
	return (src[0]  ^ src[1]  ^ src[2]  ^ src[3]  ^ src[4]  ^ src[5]  ^ src[6]  ^ src[7]  ^ src[8]  ^ src[9]  ^ src[10] ^ src[11] ^ src[12] ^ src[13] ^ src[14] ^ src[15])
	| ((src[16] ^ src[17] ^ src[18] ^ src[19] ^ src[20] ^ src[21] ^ src[22] ^ src[23] ^ src[24] ^ src[25] ^ src[26] ^ src[27] ^ src[28] ^ src[29] ^ src[30] ^ src[31]) << 8);
}

unsigned char *msg2evp(unsigned char * const msg, const size_t lenMsg, const unsigned char epk[AEM_EPK_KEYLEN], const uint16_t * const usedIds, const int usedIdCount, size_t * const lenEvp) {
	if (msg == NULL || lenMsg <= AEM_MSG_HDR_SZ || lenMsg > AEM_MSG_MAXSIZE) return NULL;

	const size_t lenPadding = ((AEM_EVP_OVERHEAD + lenMsg) % AEM_EVP_BLOCKSIZE == 0) ? 0 : AEM_EVP_BLOCKSIZE - ((AEM_EVP_OVERHEAD + lenMsg) % AEM_EVP_BLOCKSIZE);
	*lenEvp = AEM_EVP_OVERHEAD + lenMsg + lenPadding;

	unsigned char * const evp = malloc(*lenEvp);
	if (evp == NULL) {syslog(LOG_ERR, "Failed envelope alloc"); return NULL;}

	// Generate the shared secret, stored encrypted in the Envelope (decryptable with the Envelope Secret Key, known only by the user)
	unsigned char secret[crypto_kem_SHAREDSECRETBYTES];

	if (usedIds != NULL) {
		for (;;) { // Generate a shared secret with a corresponding EnvelopeID that's unused
			if (crypto_kem_enc(evp, secret, epk) != 0) {syslog(LOG_ERR, "Failed kem"); return NULL;}

			bool found = false;
			for (int i = 0; i < usedIdCount; i++) {
				if (usedIds[i] == getEnvelopeId(evp)) {
					found = true;
					break;
				}
			}
			if (!found) break;
		}
	} else { // No list supplied
		for (;;) { // Generate a shared secret where EnvelopeID=0
			if (crypto_kem_enc(evp, secret, epk) != 0) {syslog(LOG_ERR, "Failed kem"); return NULL;}
			if (getEnvelopeId(evp) == 0) break;
		}
	}

	// Prepare raw data
	evp[crypto_kem_CIPHERTEXTBYTES] = lenPadding;
	memcpy(evp + AEM_EVP_OVERHEAD, msg, lenMsg);
	if (lenPadding > 0) randombytes_buf(evp + AEM_EVP_OVERHEAD + lenMsg, lenPadding);

	// Encrypt the Message into the Envelope with AES256-CTR
	bool ok = true;

	Aes aes;
	wc_AesInit(&aes, NULL, INVALID_DEVID);

	// Use block count as nonce to harden against attackers who don't know the size (stored in the Stindex)
	const int bc = MIN(UINT16_MAX, (*lenEvp / AEM_EVP_BLOCKSIZE) - AEM_EVP_MINBLOCKS);
	if (wc_AesSetKey(&aes, secret, crypto_kem_SHAREDSECRETBYTES, (unsigned char[16]){0,0,0,0,0,0,0,0,0,0,0,0,0,0, bc & 255, bc >> 8}, AES_ENCRYPTION) != 0) {
		syslog(LOG_ERR, "Failed Envelope setkey");
		ok = false;
	}

	if (wc_AesCtrEncrypt(&aes, evp + crypto_kem_CIPHERTEXTBYTES, evp + crypto_kem_CIPHERTEXTBYTES, lenMsg + 1 + lenPadding) != 0) {
		syslog(LOG_ERR, "Failed Envelope encrypt");
		ok = false;
	}

	// Clean up
	sodium_memzero(msg, lenMsg);
	sodium_memzero(secret, crypto_kem_SHAREDSECRETBYTES);
	wc_AesFree(&aes);

	if (!ok) {
		sodium_memzero(evp, *lenEvp);
		free(evp);
		return NULL;
	}

	return evp;
}
