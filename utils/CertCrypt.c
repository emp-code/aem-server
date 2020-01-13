//	CertCrypt: Encrypts TLS cert/key files for All-Ears Mail
//	Compile: gcc -lsodium CertCrypt.c -o CertCrypt

#include <ctype.h> // for isxdigit
#include <fcntl.h> // for open
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h> // for memset
#include <termios.h>
#include <unistd.h> // for write

#define AEM_MAXSIZE_FILE 8192

unsigned char master[crypto_secretbox_KEYBYTES];

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
	sodium_memzero(masterHex, crypto_secretbox_KEYBYTES);
	return 0;
}

int main(int argc, char *argv[]) {
	puts("CertCrypt: Encrypt .key or .crt files for All-Ears Mail");

	if (argc < 2 || strlen(argv[1]) < 5 || (strcmp(argv[1] + strlen(argv[1]) - 4, ".key") != 0 && strcmp(argv[1] + strlen(argv[1]) - 4, ".crt") != 0)) {
		puts("Terminating: Use .key or .crt file as parameter");
		return EXIT_FAILURE;
	}

	if (sodium_init() < 0) {
		puts("Terminating: Failed to initialize libsodium");
		return EXIT_FAILURE;
	}

	if (getKey() != 0) {
		puts("Terminating: Key input failed");
		return EXIT_FAILURE;
	}

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed to open file");
		return EXIT_FAILURE;
	}

	unsigned char buf[AEM_MAXSIZE_FILE];
	const off_t bytes = read(fd, buf, AEM_MAXSIZE_FILE);
	close(fd);
	if (bytes < 1) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		puts("Terminating: Failed to read file");
		return EXIT_FAILURE;
	}

	const size_t lenEncrypted = bytes + crypto_secretbox_MACBYTES;
	unsigned char encrypted[lenEncrypted];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

	crypto_secretbox_easy(encrypted, buf, bytes, nonce, master);
	sodium_memzero(buf, bytes);

	char path[strlen(argv[1]) + 5];
	sprintf(path, "%s.enc", argv[1]);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		printf("Terminating: Failed to create %s\n", path);
		return EXIT_FAILURE;
	}

	int ret = write(fd, nonce, crypto_secretbox_NONCEBYTES);
	ret += write(fd, encrypted, lenEncrypted);
	close(fd);

	if (ret != crypto_secretbox_NONCEBYTES + lenEncrypted) {
		sodium_memzero(master, crypto_secretbox_KEYBYTES);
		printf("Failed to write %s\n", path);
		return EXIT_FAILURE;
	}

	printf("Created %s\n", path);

	sodium_memzero(master, crypto_secretbox_KEYBYTES);
	return 0;
}
