#include <string.h>

#include <sodium.h>

#include "../Global.h"

#include "Envelope.h"

// ID based on the envelope's first 32 bytes
uint16_t getEnvelopeId(const unsigned char * const src) {
	const unsigned char id[] = {
		src[0]  ^ src[1]  ^ src[2]  ^ src[3]  ^ src[4]  ^ src[5]  ^ src[6]  ^ src[7]  ^ src[8]  ^ src[9]  ^ src[10] ^ src[11] ^ src[12] ^ src[13] ^ src[14] ^ src[15],
		src[16] ^ src[17] ^ src[18] ^ src[19] ^ src[20] ^ src[21] ^ src[22] ^ src[23] ^ src[24] ^ src[25] ^ src[26] ^ src[27] ^ src[28] ^ src[29] ^ src[30] ^ src[31]
	};

	return *(const uint16_t * const)id;
}

// TODO: Security Envelope
//ek->security to determine evp type

// Weak Envelope: X25519
unsigned char *msg2evp(const unsigned char * const msg, const size_t lenMsg, const unsigned char epk[X25519_PKBYTES], const uint16_t * const usedIds, const int usedIdCount, size_t * const lenEvp) {
	if (msg == NULL || lenMsg <= AEM_MSG_HDR_SZ || lenMsg > AEM_MSG_W_MAXSIZE) return NULL;

	const size_t lenPadding = ((AEM_EVP_W_OVERHEAD + lenMsg) % AEM_EVP_BLOCKSIZE == 0) ? 0 : AEM_EVP_BLOCKSIZE - ((AEM_EVP_W_OVERHEAD + lenMsg) % AEM_EVP_BLOCKSIZE);
	*lenEvp = AEM_EVP_W_OVERHEAD + lenMsg + lenPadding;

	unsigned char * const evp = malloc(*lenEvp);
	if (evp == NULL) return NULL;

	// Generate a random X25519 secret key, and store the public key in the Envelope
	unsigned char x25519_sk[X25519_SKBYTES];

	if (usedIds != NULL) {
		for (;;) { // Generate a PK with a corresponding EnvelopeID that's unused
			randombytes_buf(x25519_sk, X25519_SKBYTES);
			crypto_scalarmult_base(evp, x25519_sk);

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
		for (;;) { // Generate a PK where EnvelopeID=0
			randombytes_buf(x25519_sk, X25519_SKBYTES);
			crypto_scalarmult_base(evp, x25519_sk);
			if (getEnvelopeId(evp) == 0) break;
		}
	}

	// Add the padding amount, message, and padding
	evp[X25519_PKBYTES] = lenPadding;
	memcpy(evp + AEM_EVP_W_OVERHEAD, msg, lenMsg);
	if (lenPadding > 0) randombytes_buf(evp + AEM_EVP_W_OVERHEAD + lenMsg, lenPadding);

	// Base: Create the shared secret from our secret key and user's the Envelope Public Key (EPK). Erase our secret key.
	const size_t lenBase = crypto_scalarmult_BYTES + X25519_PKBYTES + sizeof(uint16_t);
	unsigned char base[lenBase];
	if (crypto_scalarmult(base, x25519_sk, epk) != 0) {free(evp); return NULL;}
	sodium_memzero(x25519_sk, X25519_SKBYTES);

	// Base: Add EPK and block count
	memcpy(base + crypto_scalarmult_BYTES, epk, X25519_PKBYTES);
	const uint16_t blockCount = (*lenEvp / AEM_EVP_BLOCKSIZE) - AEM_EVP_MINBLOCKS;
	memcpy(base + crypto_scalarmult_BYTES + X25519_PKBYTES, &blockCount, sizeof(uint16_t));

	// Create 368 bits of nonce-counter-key from the Base, and erase it
	unsigned char nck[crypto_stream_chacha20_ietf_KEYBYTES + crypto_stream_chacha20_ietf_NONCEBYTES + sizeof(uint16_t)];
	crypto_generichash(nck, crypto_stream_chacha20_ietf_KEYBYTES + crypto_stream_chacha20_ietf_NONCEBYTES + sizeof(uint16_t), base, lenBase, NULL, 0);
	sodium_memzero(base, lenBase);

	// ChaCha20 in-place encryption; erase nonce-counter-key
	crypto_stream_chacha20_ietf_xor_ic(
		/* Ciphertext */ evp + X25519_PKBYTES,
		/* Sourcetext */ evp + X25519_PKBYTES,
		/* Length */ *lenEvp - X25519_PKBYTES,
		/*  96 bits: Nonce   */ nck,
		/*  16 bits: Counter */ *(uint16_t*)(nck + crypto_stream_chacha20_ietf_NONCEBYTES) << 16,
		/* 256 bits: Key     */ nck + crypto_stream_chacha20_ietf_NONCEBYTES + sizeof(uint16_t)
	);
	sodium_memzero(nck, crypto_stream_chacha20_ietf_KEYBYTES + crypto_stream_chacha20_ietf_NONCEBYTES + sizeof(uint16_t));

	return evp;
}
