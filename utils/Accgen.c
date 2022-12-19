// Accgen.c: Generate Account.aem for All-Ears Mail

#include <fcntl.h>
#include <locale.h> // for setlocale
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/types.h>
#include <ctype.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/LoadEnc.h"
#include "../account/aem_user.h"

int main(void) {
	setlocale(LC_ALL, "C");
	if (sodium_init() != 0) {puts("Terminating: Failed sodium_init()"); return EXIT_FAILURE;}

	static unsigned char key_account[crypto_secretbox_KEYBYTES];
	if (loadEnc(AEM_PATH_KEY_ACC, crypto_secretbox_KEYBYTES, key_account) != 0) return EXIT_FAILURE;

	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	unsigned char mk[crypto_kdf_KEYBYTES];
	unsigned char se[crypto_box_SEEDBYTES];
	unsigned char pv[crypto_secretbox_KEYBYTES];
	crypto_kdf_keygen(mk);
	crypto_kdf_derive_from_key(se, crypto_box_SEEDBYTES, 1, "AEM-Usr0", mk);
	crypto_kdf_derive_from_key(pv, crypto_secretbox_KEYBYTES, 5, "AEM-Usr0", mk);
	crypto_box_seed_keypair(pk, sk, se);
	sodium_memzero(sk, crypto_box_SECRETKEYBYTES);
	sodium_memzero(se, crypto_box_SEEDBYTES);

	struct aem_user admin;
	bzero(&admin, sizeof(struct aem_user));
	admin.info = 3;
	memcpy(admin.upk, pk, crypto_box_PUBLICKEYBYTES);

	// Private data field, encrypted zeroes
	const size_t lenZero = AEM_LEN_PRIVATE - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
	unsigned char zero[lenZero];
	bzero(zero, lenZero);

	randombytes_buf(admin.private, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(admin.private + crypto_secretbox_NONCEBYTES, zero, lenZero, admin.private, pv);
	sodium_memzero(pv, crypto_secretbox_KEYBYTES);

	// Pad
	const size_t lenPadded = 4 + sizeof(struct aem_user) * 1024;
	unsigned char * const padded = malloc(lenPadded);
	if (padded == NULL) return EXIT_FAILURE;

	const uint32_t padAmount = sizeof(struct aem_user) * 1023;
	memcpy(padded, &padAmount, 4);
	memcpy(padded + 4, (unsigned char*)&admin, sizeof(struct aem_user));
	randombytes_buf_deterministic(padded + 4 + sizeof(struct aem_user), lenPadded - 4 - sizeof(struct aem_user), padded);

	// Encrypt with Account Key
	const size_t lenEncrypted = lenPadded + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
	unsigned char * const encrypted = malloc(lenEncrypted);
	if (encrypted == NULL) {free(padded); return EXIT_FAILURE;}
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, padded, lenPadded, encrypted, key_account);
	free(padded);

	const int fd = open("Account.aem", O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) {
		free(encrypted);
		puts("Failed creating Account.aem");
		return EXIT_FAILURE;
	}

	if (write(fd, encrypted, lenEncrypted) != lenEncrypted) {
		close(fd);
		free(encrypted);
		perror("Failed writing Account.aem");
		return EXIT_FAILURE;
	}

	free(encrypted);
	close(fd);

	const size_t lenHex = crypto_kdf_KEYBYTES * 2 + 1;
	char hex[lenHex];
	sodium_bin2hex(hex, lenHex, mk, crypto_kdf_KEYBYTES);
	sodium_memzero(mk, crypto_kdf_KEYBYTES);
	puts("Created Account.aem with admin user");
	printf("Secret Key (hex): %s\n", hex);
	sodium_memzero(hex, crypto_box_SECRETKEYBYTES * 2);

	return 0;
}
