// Keygen: Generate key files for All-Ears Mail

#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h> // for open
#include <unistd.h> // for write

#include <sodium.h>

#include "../Global.h"

#define AEK_PATH_KEY_ACC "Account.key"
#define AEK_PATH_KEY_API "API.key"
#define AEK_PATH_KEY_MNG "Manager.key"
#define AEK_PATH_KEY_SIG "Signing.key"
#define AEK_PATH_KEY_STO "Storage.key"

#define AEK_PATH_DKI_ADM "Admin.dkim"
#define AEK_PATH_DKI_USR "Users.dkim"

#define AEK_PATH_SLT_NRM "Normal.slt"
#define AEK_PATH_SLT_SHD "Shield.slt"
#define AEK_PATH_SLT_FKE "Fake.slt"

static unsigned char master[crypto_secretbox_KEYBYTES];

static int writeRandomEncrypted(const char * const path, const size_t len) {
	const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) {
		printf("Failed creating %s\n", path);
		return -1;
	}

	unsigned char buf[len];
	randombytes_buf(buf, len);

	const size_t lenEncrypted = len + crypto_secretbox_MACBYTES;
	unsigned char encrypted[lenEncrypted];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted, buf, len, nonce, master);
	sodium_memzero(buf, len);

	ssize_t ret = write(fd, nonce, crypto_secretbox_NONCEBYTES);
	ret += write(fd, encrypted, lenEncrypted);
	close(fd);

	if ((unsigned long)ret != crypto_secretbox_NONCEBYTES + lenEncrypted) {
		printf("Failed writing %s\n", path);
		return -1;
	}

	printf("Created %s\n", path);
	return 0;
}

int main(void) {
	puts("Keygen: Generate key files for All-Ears Mail");

	if (sodium_init() < 0) {
		puts("Terminating: Failed initializing libsodium");
		return EXIT_FAILURE;
	}

	crypto_secretbox_keygen(master);

	const size_t lenHex = crypto_secretbox_KEYBYTES * 2 + 1;
	char master_hex[lenHex];
	sodium_bin2hex(master_hex, lenHex, master, crypto_secretbox_KEYBYTES);
	printf("Master Key (hex): %s\n", master_hex);
	sodium_memzero(master_hex, lenHex);

	writeRandomEncrypted(AEK_PATH_KEY_ACC, AEM_LEN_KEY_ACC);
	writeRandomEncrypted(AEK_PATH_KEY_API, AEM_LEN_KEY_API);
	writeRandomEncrypted(AEK_PATH_KEY_MNG, AEM_LEN_KEY_MNG);
	writeRandomEncrypted(AEK_PATH_KEY_SIG, AEM_LEN_KEY_SIG);
	writeRandomEncrypted(AEK_PATH_KEY_STO, AEM_LEN_KEY_STO);
	writeRandomEncrypted(AEK_PATH_SLT_SHD, AEM_LEN_SLT_SHD);

	sodium_memzero(master, crypto_secretbox_KEYBYTES);
	return 0;
}
