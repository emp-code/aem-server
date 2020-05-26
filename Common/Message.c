static uint16_t msg_getPadAmount(const int lenContent) {
	const unsigned int lenUnpadded = lenContent + crypto_sign_BYTES;
	return ((lenUnpadded + crypto_box_SEALBYTES) % 1024 == 0) ? 0 : 1024 - ((lenUnpadded + crypto_box_SEALBYTES) % 1024);
}

static unsigned char *msg_encrypt(const unsigned char * const content, const size_t lenContent, size_t * const lenEncrypted) {
	const uint16_t padAmount = msg_getPadAmount(lenContent);
	const size_t lenPadded = lenContent + padAmount + crypto_sign_BYTES;

	unsigned char * const clear = sodium_malloc(lenPadded);
	memcpy(clear, content, lenContent);
	randombytes_buf_deterministic(clear + lenContent, padAmount, clear); // First randombytes_SEEDBYTES determine the padding bytes
	crypto_sign_detached(clear + lenPadded - crypto_sign_BYTES, NULL, clear, lenPadded - crypto_sign_BYTES, sign_skey);

	*lenEncrypted = lenPadded + crypto_box_SEALBYTES;
	unsigned char *encrypted = malloc(*lenEncrypted);
	const int ret = crypto_box_seal(encrypted, clear, lenPadded, upk);
	sodium_free(clear);

	if (ret != 0) {
		free(encrypted);
		return NULL;
	}

	return encrypted;
}
