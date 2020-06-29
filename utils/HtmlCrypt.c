// HtmlCrypt.c: Encrypt index.html for All-Ears Mail
// Copy the resulting file to /etc/allears/index.html

#include <fcntl.h> // for open
#include <stdio.h>
#include <string.h>
#include <unistd.h> // for write

#include <sodium.h>

#include "../Global.h"

#include "GetKey.h"

static unsigned char master[crypto_secretbox_KEYBYTES];

int main(void) {
	puts("HtmlCrypt: Encrypt index.html for All-Ears Mail");

	if (sodium_init() < 0) {puts("Terminating: Failed initializing libsodium"); return EXIT_FAILURE;}
	if (getKey(master) != 0) {puts("Terminating: Failed reading key"); return EXIT_FAILURE;}

	int fd = open("index.html", O_RDONLY);
	if (fd < 0) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed opening index.html");
		return EXIT_FAILURE;
	}

	const off_t lenClear = lseek(fd, 0, SEEK_END);
	unsigned char clear[lenClear];
	const off_t readBytes = pread(fd, clear, lenClear, 0);
	close(fd);

	if (readBytes != lenClear) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed reading index.html");
		return EXIT_FAILURE;
	}

	const size_t lenEncrypted = lenClear + crypto_secretbox_MACBYTES;
	unsigned char encrypted[lenEncrypted];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted, clear, lenClear, nonce, master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);

	fd = open("index.html.enc", O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) {
		puts("Terminating: Failed creating index.html.enc");
		return EXIT_FAILURE;
	}

	int ret = write(fd, nonce, crypto_secretbox_NONCEBYTES);
	ret += write(fd, encrypted, lenEncrypted);
	close(fd);

	if ((unsigned long)ret != crypto_secretbox_NONCEBYTES + lenEncrypted) {
		puts("Terminating: Failed writing index.html.enc");
		return EXIT_FAILURE;
	}

	puts("Created index.html.enc");
	return EXIT_SUCCESS;
}
