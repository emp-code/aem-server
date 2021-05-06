static uint8_t msg_getPadAmount(const size_t lenContent) {
	const size_t lenUnpadded = lenContent + crypto_sign_BYTES;
	return ((lenUnpadded + crypto_box_SEALBYTES) % 16 == 0) ? 0 : 16 - ((lenUnpadded + crypto_box_SEALBYTES) % 16);
}

static unsigned char *msg_encrypt(const unsigned char * const pk, const unsigned char * const content, const size_t lenContent, size_t * const lenEncrypted) {
	const uint8_t padAmount = msg_getPadAmount(lenContent);
	const size_t lenPadded = lenContent + padAmount + crypto_sign_BYTES;

	unsigned char * const clear = sodium_malloc(lenPadded);
	if (clear == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}

	memcpy(clear, content, lenContent);
	randombytes_buf_deterministic(clear + lenContent, padAmount, clear); // First randombytes_SEEDBYTES determine the padding bytes
	crypto_sign_detached(clear + lenPadded - crypto_sign_BYTES, NULL, clear, lenPadded - crypto_sign_BYTES, sign_skey);

	*lenEncrypted = lenPadded + crypto_box_SEALBYTES;
	unsigned char *encrypted = malloc(*lenEncrypted);
	if (encrypted == NULL) {syslog(LOG_ERR, "Failed allocation"); sodium_free(clear); return NULL;}

	const int ret = crypto_box_seal(encrypted, clear, lenPadded, pk);
	sodium_free(clear);

	if (ret != 0) {
		free(encrypted);
		return NULL;
	}

	return encrypted;
}
