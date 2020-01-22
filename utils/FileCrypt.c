// FileCrypt.c: Encrypt files for All-Ears Mail
// Place resulting files in /etc/allears (remove the .enc extension)
// Compile: gcc -lsodium -lbrotlienc FileCrypt.c -o FileCrypt

#include <ctype.h> // for isxdigit
#include <fcntl.h> // for open
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h> // for write

#include "../Common/Brotli.c"

static unsigned char master[crypto_secretbox_KEYBYTES];

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

static int getKey(void) {
	toggleEcho(false);

	puts("Enter Master Key (hex) - will not echo");

	char masterHex[crypto_secretbox_KEYBYTES * 2];
	for (unsigned int i = 0; i < crypto_secretbox_KEYBYTES * 2; i++) {
		const int gc = getchar();
		if (gc == EOF || !isxdigit(gc)) {toggleEcho(true); return -1;}
		masterHex[i] = gc;
	}

	toggleEcho(true);

	sodium_hex2bin(master, crypto_secretbox_KEYBYTES, masterHex, crypto_secretbox_KEYBYTES * 2, NULL, NULL, NULL);
	sodium_memzero(masterHex, crypto_secretbox_KEYBYTES * 2);
	return 0;
}

int main(int argc, char *argv[]) {
	puts("allears-encrypt: Encrypt files for All-Ears Mail");

	if (argc < 2) {puts("Terminating: Use filename as parameter"); return EXIT_FAILURE;}
	if (sodium_init() < 0) {puts("Terminating: Failed to initialize libsodium"); return EXIT_FAILURE;}
	if (getKey() != 0) {puts("Terminating: Key input failed"); return EXIT_FAILURE;}

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed to open file");
		return EXIT_FAILURE;
	}

	const off_t clearBytes = lseek(fd, 0, SEEK_END);
	unsigned char *buf = malloc(clearBytes);
	off_t readBytes = pread(fd, buf, clearBytes, 0);
	close(fd);

	if (readBytes < 1) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed to read file");
		return EXIT_FAILURE;
	}

	size_t bytes = clearBytes;
	int ret = brotliCompress(&buf, &bytes);
	if (ret != 0) {
		free(buf);
		puts("Terminating: Failed to compress");
		return EXIT_FAILURE;
	}

	const size_t lenEncrypted = bytes + crypto_secretbox_MACBYTES;
	unsigned char encrypted[lenEncrypted];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted, buf, bytes, nonce, master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);

	char path[strlen(argv[1]) + 5];
	sprintf(path, "%s.enc", argv[1]);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) {
		printf("Terminating: Failed to create %s\n", path);
		return EXIT_FAILURE;
	}

	ret = write(fd, nonce, crypto_secretbox_NONCEBYTES);
	ret += write(fd, encrypted, lenEncrypted);
	close(fd);

	if (ret != crypto_secretbox_NONCEBYTES + lenEncrypted) {
		printf("Failed to write %s\n", path);
		return EXIT_FAILURE;
	}

	printf("Created %s\n", path);
	return EXIT_SUCCESS;
}
