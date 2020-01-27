#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <locale.h> // for setlocale
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

#define AEM_PORT_MANAGER "940"
#define AEM_MAXPROCESSES 25
#define AEM_LEN_MSG 1024 // must be at least AEM_MAXPROCESSES * 3 * 4
#define AEM_LEN_ENCRYPTED (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + AEM_LEN_MSG)
#define AEM_PATH_KEY_MNG "/etc/allears/Manager.key"

unsigned char key_manager[crypto_secretbox_KEYBYTES];

static int makeSocket(const char * const host) {
	struct addrinfo hints;
	struct addrinfo *res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, AEM_PORT_MANAGER, &hints, &res) != 0) {
		puts("getaddrinfo failed");
		return -1;
	}

	const int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	connect(sock, res->ai_addr, res->ai_addrlen);
	free(res);
	return sock;
}

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
	// Load Manager Key box
	const int fd = open(AEM_PATH_KEY_MNG, O_RDONLY);
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

	// Open Manager Key box
	const int ret = crypto_secretbox_open_easy(key_manager, encrypted, crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES, nonce, master);
	sodium_memzero(master, crypto_secretbox_KEYBYTES);
	return ret;
}

static void cryptSend(const int sock, const unsigned char comChar, const unsigned char comType, const uint32_t comNum) {
	unsigned char decrypted[AEM_LEN_MSG];
	decrypted[0] = comChar; // T=Terminate, K=Kill, S=Spawn

	switch(comType) {
		case 'M': decrypted[1] = 0; break;
		case 'W': decrypted[1] = 1; break;
		case 'A': decrypted[1] = 2; break;
	}

	memcpy(decrypted + 2, &comNum, 4);
	bzero(decrypted + 6, AEM_LEN_MSG - 6);

	unsigned char encrypted[AEM_LEN_ENCRYPTED];
	randombytes_buf(encrypted, crypto_secretbox_NONCEBYTES);
	crypto_secretbox_easy(encrypted + crypto_secretbox_NONCEBYTES, decrypted, AEM_LEN_MSG, encrypted, key_manager);

	send(sock, encrypted, AEM_LEN_ENCRYPTED, 0);
}

int main(int argc, char *argv[]) {
	setlocale(LC_ALL, "C");

	if (argc < 2) {puts("Usage: ManagerClient domain.tld instructions"); return EXIT_FAILURE;}
	if (sodium_init() == -1) {puts("Terminating: Failed to init libsodium"); return EXIT_FAILURE;}
	if (loadKey() != 0) {puts("Terminating: Failed to load key"); return EXIT_FAILURE;}

	int sock = makeSocket(argv[1]);
	if (sock < 1) return EXIT_FAILURE;

	uint32_t comNum = 0;
	unsigned char comChar = '\0';
	unsigned char comType = '\0';
	if (argc > 2) {
		comChar = argv[2][0];
		comType = argv[2][1];
		comNum = strtol(argv[2] + 2, NULL, 10);
	}

	cryptSend(sock, comChar, comType, comNum);

	unsigned char encrypted[AEM_LEN_ENCRYPTED];
	if (recv(sock, encrypted, AEM_LEN_ENCRYPTED, 0) != AEM_LEN_ENCRYPTED) {
		puts("Receive fail");
		close(sock);
		return EXIT_FAILURE;
	}

	unsigned char decrypted[AEM_LEN_MSG];
	if (crypto_secretbox_open_easy(decrypted, encrypted + crypto_secretbox_NONCEBYTES, AEM_LEN_ENCRYPTED - crypto_secretbox_NONCEBYTES, encrypted, key_manager) != 0) {
		puts("Open fail");
		close(sock);
		return EXIT_FAILURE;
	}

	for (int i = 0; i < 3; i++) {
		for (int j = 0; j < AEM_MAXPROCESSES; j++) {
			uint32_t pid;
			memcpy(&pid, decrypted + ((i * AEM_MAXPROCESSES + j) * 4), 4);
			if (pid != 0) printf("%d/%d=%u\n", i, j, pid);
		}
	}

	close(sock);
	return EXIT_SUCCESS;
}