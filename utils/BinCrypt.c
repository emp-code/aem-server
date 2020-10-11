// BinCrypt.c: Encrypt All-Ears Mail binaries

#include <fcntl.h> // for open
#include <stdio.h>
#include <string.h>
#include <unistd.h> // for write

#include <sodium.h>

#include "../Global.h"

#include "GetKey.h"

static unsigned char master[crypto_secretbox_KEYBYTES];

int main(int argc, char *argv[]) {
	puts("BinCrypt: Encrypt All-Ears Mail binaries");

	if (argc != 2) {printf("Usage: %s input.file\n", argv[0]); return EXIT_FAILURE;}
	if (sodium_init() < 0) {puts("Terminating: Failed sodium_init()"); return EXIT_FAILURE;}
	if (getKey(master) != 0) {puts("Terminating: Failed reading key"); return EXIT_FAILURE;}

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed opening file");
		return EXIT_FAILURE;
	}

	const off_t lenClear = lseek(fd, 0, SEEK_END);
	unsigned char clear[lenClear];
	const off_t readBytes = pread(fd, clear, lenClear, 0);
	close(fd);

	if (readBytes != lenClear) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed reading file");
		return EXIT_FAILURE;
	}

	const size_t lenEncrypted = lenClear + crypto_secretbox_MACBYTES;
	unsigned char encrypted[lenEncrypted];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted, clear, lenClear, nonce, master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);

	char pathEnc[strlen(argv[1]) + 5];
	sprintf(pathEnc, "%s.enc", argv[1]);
	fd = open(pathEnc, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) {
		puts("Terminating: Failed creating file");
		return EXIT_FAILURE;
	}

	int ret = write(fd, nonce, crypto_secretbox_NONCEBYTES);
	ret += write(fd, encrypted, lenEncrypted);
	close(fd);

	if ((unsigned long)ret != crypto_secretbox_NONCEBYTES + lenEncrypted) {
		puts("Terminating: Failed writing file");
		return EXIT_FAILURE;
	}

	puts("Created file");
	return EXIT_SUCCESS;
}
