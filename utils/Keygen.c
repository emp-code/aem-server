// All-Ears Keygen: Generates keys for All-Ears Mail using libsodium
// Compile: gcc -lsodium Keygen.c -o Keygen

#include <stdio.h>
#include <sodium.h>
#include <fcntl.h> // for open
#include <unistd.h> // for write
#include <string.h> // for memset

#define AEM_PATH_KEY_ADR "Address.key"
#define AEM_PATH_KEY_API "API.key"
#define AEM_PATH_KEY_MNG "Manager.key"
#define AEM_PATH_KEY_STO "Storage.key"

#define AEM_LEN_KEY_ADR crypto_pwhash_SALTBYTES
#define AEM_LEN_KEY_API crypto_box_SECRETKEYBYTES
#define AEM_LEN_KEY_MNG crypto_secretbox_KEYBYTES
#define AEM_LEN_KEY_STO 32

// Nonces are not secret, but must not be reused with the same key
#define AEM_NONCECHAR_KEY_ADR 'a'
#define AEM_NONCECHAR_KEY_MNG 'm'
#define AEM_NONCECHAR_KEY_STO 's'
#define AEM_NONCECHAR_KEY_API 'w'
#define AEM_NONCECHAR_KEY_TLS 't'
#define AEM_NONCECHAR_CRT_TLS 'c'

unsigned char master[crypto_secretbox_KEYBYTES];

int writeRandomEncrypted(const char * const path, const size_t len, const char nonceChar) {
	const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);

	if (fd < 0) {
		printf("Failed to create %s\n", path);
		return -1;
	}

	unsigned char buf[len];
	randombytes_buf(buf, len);

	const size_t lenEncrypted = len + crypto_secretbox_MACBYTES;
	unsigned char encrypted[lenEncrypted];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	memset(nonce, nonceChar, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted, buf, len, nonce, master);
	sodium_memzero(buf, len);

	const int ret = write(fd, encrypted, lenEncrypted);
	close(fd);

	if (ret != lenEncrypted) {
		printf("Failed to write %s\n", path);
		return -1;
	}

	printf("Created %s\n", path);
	return 0;
}

int main(void) {
	puts("Key Generator for All-Ears Mail");

	if (sodium_init() < 0) {
		puts("Terminating: Failed to initialize libsodium");
		return EXIT_FAILURE;
	}

	crypto_secretbox_keygen(master);

	const size_t lenHex = crypto_secretbox_KEYBYTES * 2 + 1;
	char master_hex[lenHex];
	sodium_bin2hex(master_hex, lenHex, master, crypto_secretbox_KEYBYTES);
	printf("Master Key (hex): %s\n", master_hex);
	sodium_memzero(master_hex, lenHex);

	writeRandomEncrypted(AEM_PATH_KEY_ADR, AEM_LEN_KEY_ADR, AEM_NONCECHAR_KEY_ADR);
	writeRandomEncrypted(AEM_PATH_KEY_API, AEM_LEN_KEY_API, AEM_NONCECHAR_KEY_API);
	writeRandomEncrypted(AEM_PATH_KEY_MNG, AEM_LEN_KEY_MNG, AEM_NONCECHAR_KEY_MNG);
	writeRandomEncrypted(AEM_PATH_KEY_STO, AEM_LEN_KEY_STO, AEM_NONCECHAR_KEY_STO);

	sodium_memzero(master, crypto_secretbox_KEYBYTES);

	return 0;
}
