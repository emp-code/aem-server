// Resgen: Generate the Reserved Address List, Admin.adr
// Warning: Slow and resource-intensive (Argon2)

#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h> // for open

#include <sodium.h>

#include "../Common/Addr32.c"

#include "../Global.h"

#include "GetKey.h"

#define AEM_PATH_ADR_ADM "Admin.adr"
#define AEM_PATH_SLT_NRM "/etc/allears/Normal.slt"

unsigned char salt_normal[AEM_LEN_SALT_NORM];

unsigned char master[crypto_secretbox_KEYBYTES];

static int getSalt(void) {
	const int fd = open(AEM_PATH_SLT_NRM, O_RDONLY);
	if (fd < 0) return -1;

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	off_t readBytes = read(fd, nonce, crypto_secretbox_NONCEBYTES);
	if (readBytes != crypto_secretbox_NONCEBYTES) {close(fd); return -1;}

	unsigned char encrypted[AEM_LEN_SALT_NORM + crypto_secretbox_MACBYTES];
	readBytes = read(fd, encrypted, AEM_LEN_SALT_NORM + crypto_secretbox_MACBYTES);
	close(fd);
	if (readBytes != AEM_LEN_SALT_NORM + crypto_secretbox_MACBYTES) return -1;

	return crypto_secretbox_open_easy(salt_normal, encrypted, AEM_LEN_SALT_NORM + crypto_secretbox_MACBYTES, nonce, master);
}

__attribute__((warn_unused_result))
static uint64_t addressToHash(const unsigned char * const addr32) {
	if (addr32 == NULL) return -1;

	uint64_t halves[2];
	if (crypto_pwhash((unsigned char*)halves, 16, (const char*)addr32, 10, salt_normal, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) return 0;

	return halves[0] ^ halves[1];
}

int main(void) {
	puts("Resgen: Generate Admin.adr for All-Ears Mail");

	if (sodium_init() < 0) {
		puts("Terminating: Failed initializing libsodium");
		return EXIT_FAILURE;
	}

	getKey(master);
	getSalt();

	const int fdTxt = open("Admin.adr.txt", O_RDONLY);
	if (fdTxt < 0) {puts("Failed to open Admin.adr.txt"); sodium_memzero(master, crypto_secretbox_KEYBYTES); return EXIT_FAILURE;}

	const off_t len = lseek(fdTxt, 0, SEEK_END);
	unsigned char data[len];
	pread(fdTxt, data, len, 0);

	int fdBin = open("Admin.adr.bin", O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fdBin < 0) {close(fdTxt); sodium_memzero(master, crypto_secretbox_KEYBYTES); return EXIT_FAILURE;}

	unsigned char *s = data;
	while(1) {
		unsigned char *lf = memchr(s, '\n', (data + len) - s);
		if (lf == NULL) break;
		const size_t lenSrc = lf - s;
		if (lenSrc > 15) {puts("Line too long"); break;}

		unsigned char addr32[10];
		addr32_store(addr32, (char*)s, lenSrc);

		const uint64_t hash = addressToHash(addr32);
		write(fdBin, &hash, 8);

		s = lf + 1;
	}

	close(fdTxt);

	const off_t lenDec = lseek(fdBin, 0, SEEK_END);
	unsigned char dec[lenDec];
	pread(fdBin, dec, lenDec, 0);
	close(fdBin);

	// Write encrypted
	fdBin = open("Admin.adr.bin", O_WRONLY | O_TRUNC);

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
	write(fdBin, nonce, crypto_secretbox_NONCEBYTES);

	const size_t lenEnc = lenDec + crypto_secretbox_MACBYTES;
	unsigned char enc[lenEnc];

	crypto_secretbox_easy(enc, dec, lenDec, nonce, master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);
	sodium_memzero(dec, lenDec);

	write(fdBin, enc, lenEnc);
	close(fdBin);

	printf("Wrote %zu bytes\n", lenEnc);
	return 0;
}
