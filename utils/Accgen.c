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

#include "GetKey.h"

struct aem_user {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char info; // & 3 = level; & 4 = unused; >> 3 = addresscount
	unsigned char private[AEM_LEN_PRIVATE];
	uint64_t addrHash[AEM_ADDRESSES_PER_USER];
	unsigned char addrFlag[AEM_ADDRESSES_PER_USER];
};

static unsigned char key_account[crypto_secretbox_KEYBYTES];

static int loadKey(void) {
	// Load Account Key box
	const int fd = open(AEM_PATH_KEY_ACC, O_RDONLY);
	if (fd < 0) return -1;

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	off_t readBytes = read(fd, nonce, crypto_secretbox_NONCEBYTES);
	if (readBytes != crypto_secretbox_NONCEBYTES) {close(fd); return -1;}

	unsigned char encrypted[crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES];
	readBytes = read(fd, encrypted, crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES);
	close(fd);
	if (readBytes != crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES) return -1;

	unsigned char master[crypto_secretbox_KEYBYTES];
	getKey(master);

	// Open Account Key box
	const int ret = crypto_secretbox_open_easy(key_account, encrypted, crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES, nonce, master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);
	return ret;
}

int main(void) {
	setlocale(LC_ALL, "C");

	if (sodium_init() != 0) {puts("Terminating: Failed sodium_init()"); return EXIT_FAILURE;}
	if (loadKey() != 0) {puts("Terminating: Failed reading key"); return EXIT_FAILURE;}

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
	memcpy(admin.pubkey, pk, crypto_box_PUBLICKEYBYTES);

	// Private data field, encrypted zeroes
	const size_t lenZero = AEM_LEN_PRIVATE - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
	unsigned char zero[lenZero];
	bzero(zero, lenZero);

	randombytes_buf(admin.private, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(admin.private + crypto_secretbox_NONCEBYTES, zero, lenZero, admin.private, pv);
	sodium_memzero(pv, crypto_secretbox_KEYBYTES);

	// Pad
	const size_t lenPadded = 4 + sizeof(struct aem_user) * 1024;
	unsigned char * const padded = sodium_malloc(lenPadded);

	const uint32_t padAmount = sizeof(struct aem_user) * 1023;
	memcpy(padded, &padAmount, 4);
	memcpy(padded + 4, (unsigned char*)&admin, sizeof(struct aem_user));
	randombytes_buf_deterministic(padded + 4 + sizeof(struct aem_user), lenPadded - 4 - sizeof(struct aem_user), padded);

	// Encrypt with Account Key
	const size_t lenEncrypted = lenPadded + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
	unsigned char * const encrypted = malloc(lenEncrypted);
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, padded, lenPadded, encrypted, key_account);
	sodium_free(padded);

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
