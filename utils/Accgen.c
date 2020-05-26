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

#define AEM_PATH_KEY_ACC "/etc/allears/Account.key"

struct aem_user {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char info; // & 3 = level; >> 2 = addresscount
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

	if (sodium_init() != 0) {puts("Terminating: Failed initializing libsodium"); return EXIT_FAILURE;}
	if (loadKey() != 0) {puts("Terminating: Failed reading key"); return EXIT_FAILURE;}

	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(pk, sk);

	struct aem_user admin;
	bzero(&admin, sizeof(struct aem_user));
	admin.info = 3;
	memcpy(admin.pubkey, pk, crypto_box_PUBLICKEYBYTES);

	const size_t lenZero = AEM_LEN_PRIVATE - crypto_box_SEALBYTES;
	unsigned char zero[lenZero];
	bzero(zero, lenZero);
	crypto_box_seal(admin.private, zero, lenZero, admin.pubkey);

	// Pad
	const uint32_t padAmount = sizeof(struct aem_user) * 1023;

	const size_t lenPadded = 4 + sizeof(struct aem_user) * 1024;
	unsigned char * const padded = sodium_malloc(lenPadded);

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

	const size_t lenHex = crypto_box_SECRETKEYBYTES * 2 + 1;
	char hex[lenHex];
	sodium_bin2hex(hex, lenHex, sk, crypto_box_SECRETKEYBYTES);
	sodium_memzero(sk, crypto_box_SECRETKEYBYTES);
	puts("Created Account.aem with admin user");
	printf("Secret Key (hex): %s\n", hex);
	sodium_memzero(hex, crypto_box_SECRETKEYBYTES * 2);

	return 0;
}
