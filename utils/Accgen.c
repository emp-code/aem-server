// Accgen.c: Generate Account.aem for All-Ears Mail
// Compile: gcc -lsodium Accgen.c -o Accgen

#include <fcntl.h>
#include <locale.h> // for setlocale
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/types.h>
#include <termios.h>
#include <ctype.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"

#define AEM_PATH_KEY_ACC "/etc/allears/Account.key"

struct aem_user {
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char level;
	unsigned char addrNormal;
	unsigned char addrShield;
	unsigned char private[AEM_LEN_PRIVATE];
	unsigned char addrHash[AEM_ADDRESSES_PER_USER][13];
	unsigned char addrFlag[AEM_ADDRESSES_PER_USER];
};

static unsigned char key_account[crypto_secretbox_KEYBYTES];

static void toggleEcho(const bool on) {
	struct termios t;
	if (tcgetattr(STDIN_FILENO, &t) != 0) return;

	if (on) {
		t.c_lflag |= ((tcflag_t)ECHO);
		t.c_lflag |= ((tcflag_t)ICANON);
	} else {
		t.c_lflag &= ~((tcflag_t)ECHO);
		t.c_lflag &= ~((tcflag_t)ICANON);
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

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

	// Get Master Key
	toggleEcho(false);

	puts("Enter Master Key (hex) - will not echo");

	char masterHex[crypto_secretbox_KEYBYTES * 2];
	for (unsigned int i = 0; i < crypto_secretbox_KEYBYTES * 2; i++) {
		const int gc = getchar();
		if (gc == EOF || !isxdigit(gc)) {toggleEcho(true); return -1;}
		masterHex[i] = gc;
	}

	toggleEcho(true);

	unsigned char master[crypto_secretbox_KEYBYTES];
	sodium_hex2bin(master, crypto_secretbox_KEYBYTES, masterHex, crypto_secretbox_KEYBYTES * 2, NULL, NULL, NULL);
	sodium_memzero(masterHex, crypto_secretbox_KEYBYTES);

	// Open Account Key box
	const int ret = crypto_secretbox_open_easy(key_account, encrypted, crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES, nonce, master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);
	return ret;
}

int main(void) {
	setlocale(LC_ALL, "C");

	if (sodium_init() != 0) {puts("Terminating: Failed to init libsodium"); return EXIT_FAILURE;}
	if (loadKey() != 0) {puts("Terminating: Failed to load key"); return EXIT_FAILURE;}

	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(pk, sk);

	struct aem_user admin;
	admin.level = AEM_USERLEVEL_MAX;
	admin.addrNormal = 0;
	admin.addrShield = 0;
	memcpy(admin.pubkey, pk, crypto_box_PUBLICKEYBYTES);

	bzero(admin.addrHash, AEM_ADDRESSES_PER_USER * 13);
	bzero(admin.addrFlag, AEM_ADDRESSES_PER_USER);

	const size_t lenZero = AEM_LEN_PRIVATE - crypto_box_SEALBYTES;
	unsigned char zero[lenZero];
	bzero(zero, lenZero);
	crypto_box_seal(admin.private, zero, lenZero, admin.pubkey);

	// Pad
	const uint32_t lenPadding = sizeof(struct aem_user) * 1023;

	const size_t lenPadded = 4 + sizeof(struct aem_user) * 1024;
	unsigned char * const padded = sodium_malloc(lenPadded);

	memcpy(padded, &lenPadding, 4);
	memcpy(padded + 4, (unsigned char*)&admin, sizeof(struct aem_user));
	randombytes_buf_deterministic(padded + 4 + sizeof(struct aem_user), lenPadded - 4 - sizeof(struct aem_user), padded);

	// Encrypt with Account Key
	const size_t lenEncrypted = lenPadded + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
	unsigned char encrypted[lenEncrypted];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, padded, lenPadded, encrypted, key_account);
	sodium_free(padded);

	const int fd = open("Account.aem", O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) {
		puts("Failed to create Account.aem");
		return EXIT_FAILURE;
	}

	if (write(fd, encrypted, lenEncrypted) != lenEncrypted) {
		perror("Failed to write Account.aem");
		close(fd);
		return EXIT_FAILURE;
	}

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
