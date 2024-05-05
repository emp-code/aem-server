#include <string.h>

#include <sodium.h>

#include "../Global.h"
#include "Signature.h"

#include "Envelope.h"

// Target is the Message to be converted into an Envelope, with AEM_ENVELOPE_RESERVED_LEN unused bytes in the beginning
void message_into_envelope(unsigned char * const target, const int lenTarget, const unsigned char epk[X25519_PKBYTES]) {
	aem_sign_message(target, lenTarget);

	// Generate a random X25519 secret key, and store the public key in the beginning of the Envelope
	unsigned char x25519_sk[X25519_SKBYTES];
	randombytes_buf(x25519_sk, X25519_SKBYTES);
	crypto_scalarmult_base(target, x25519_sk);

	// Base: Create the shared secret from our secret key and user's the Envelope Public Key (EPK). Erase our secret key.
	const size_t lenBase = crypto_scalarmult_BYTES + X25519_PKBYTES + sizeof(uint16_t);
	unsigned char base[crypto_scalarmult_BYTES + X25519_PKBYTES + sizeof(uint16_t)];
	if (crypto_scalarmult(base, x25519_sk, epk) != 0) return;
	sodium_memzero(x25519_sk, X25519_SKBYTES);

	// Base: Add the EPK and message size
	memcpy(base + crypto_scalarmult_BYTES, epk, X25519_PKBYTES);
	const uint16_t blockCount = (lenTarget / 16) - AEM_ENVELOPE_MINBLOCKS;
	memcpy(base + crypto_scalarmult_BYTES + X25519_PKBYTES, &blockCount, sizeof(uint16_t));

	// Generate the key and nonce from the Base, and erase it
	unsigned char key_nonce[crypto_stream_chacha20_KEYBYTES + crypto_stream_chacha20_NONCEBYTES];
	crypto_generichash(key_nonce, crypto_stream_chacha20_KEYBYTES + crypto_stream_chacha20_NONCEBYTES, base, lenBase, NULL, 0);
	sodium_memzero(base, lenBase);

	// In-place encryption with ChaCha20
	crypto_stream_chacha20_xor(target + X25519_PKBYTES, target + X25519_PKBYTES, lenTarget - X25519_PKBYTES, key_nonce + crypto_stream_chacha20_KEYBYTES, key_nonce);
	sodium_memzero(key_nonce, crypto_stream_chacha20_KEYBYTES + crypto_stream_chacha20_NONCEBYTES);
}
