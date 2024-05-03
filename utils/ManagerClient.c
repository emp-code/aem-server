#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/GetKey.h"

static unsigned char key_mng[crypto_aead_aegis256_KEYBYTES];

static int makeSocket(const char * const host) {
	struct addrinfo hints;
	struct addrinfo *res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, AEM_PORT_MANAGER_STR, &hints, &res) != 0) {
		puts("getaddrinfo failed");
		return -1;
	}

	const int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {free(res); puts("Failed connecting"); return -1;}

	free(res);
	return sock;
}

static int cryptSend(const int sock, const unsigned char comChar, const unsigned char comType, const uint32_t comNum) {
	unsigned char dec[AEM_MANAGER_CMDLEN_DEC];
	dec[0] = comChar; // T=Terminate, K=Kill, S=Spawn

	switch (comType) {
		case 'A': dec[1] = AEM_PROCESSTYPE_API; break;
		case 'M': dec[1] = AEM_PROCESSTYPE_MTA; break;
		case 'W': dec[1] = AEM_PROCESSTYPE_WEB; break;
		default: puts("Invalid type"); return -1;
	}

	memcpy(dec + 2, &comNum, 4);

	unsigned char enc[AEM_MANAGER_CMDLEN_ENC];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);
	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, dec, AEM_MANAGER_CMDLEN_DEC, NULL, 0, NULL, enc, key_mng);

	const int ret = send(sock, enc, AEM_MANAGER_CMDLEN_ENC, 0);
	if (ret == AEM_MANAGER_CMDLEN_ENC) return 0;

	if (ret < 0) perror("send");
	else printf("Sent %d/%d\n", ret, AEM_MANAGER_CMDLEN_ENC);
	return -1;
}

static char numToChar(const unsigned char n) {
	switch (n) {
		case AEM_PROCESSTYPE_API: return 'A';
		case AEM_PROCESSTYPE_MTA: return 'M';
		case AEM_PROCESSTYPE_WEB: return 'W';
	}

	return '?';
}

static int setKey(void) {
	unsigned char smk[AEM_KDF_KEYSIZE];
	if (getKey(smk) != 0) return -1;
	aem_kdf(key_mng, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_SMK_MNG, smk);
	sodium_memzero(smk, AEM_KDF_KEYSIZE);
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {puts("Usage: ManagerClient domain.tld instructions"); return EXIT_FAILURE;}
	if (sodium_init() != 0) {puts("Failed sodium_init()"); return EXIT_FAILURE;}
	if (setKey() != 0) return EXIT_FAILURE;

	int sock = makeSocket(argv[1]);
	if (sock < 0) return EXIT_FAILURE;

	if (argc == 4) {
		unsigned char comChar = argv[2][0];
		unsigned char comType = argv[2][1];
		uint32_t comNum = strtol(argv[3], NULL, 10);

		if (cryptSend(sock, comChar, comType, comNum) != 0) {
			close(sock);
			return EXIT_FAILURE;
		}
	} else {
		if (cryptSend(sock, 0, 0, 0) != 0) {
			close(sock);
			return EXIT_FAILURE;
		}
	}

	unsigned char enc[AEM_MANAGER_RESLEN_ENC];
	if (recv(sock, enc, AEM_MANAGER_RESLEN_ENC, MSG_WAITALL) != AEM_MANAGER_RESLEN_ENC) {
		printf("Failed recv: %m\n");
		close(sock);
		return EXIT_FAILURE;
	}

	unsigned char dec[AEM_MANAGER_RESLEN_DEC];
	if (crypto_aead_aegis256_decrypt(dec, NULL, NULL, enc + crypto_aead_aegis256_NPUBBYTES, AEM_MANAGER_RESLEN_DEC + crypto_aead_aegis256_ABYTES, NULL, 0, enc, key_mng) != 0) {
		puts("Failed decrypt");
		close(sock);
		return EXIT_FAILURE;
	}

	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < AEM_MAXPROCESSES; j++) {
			uint32_t pid;
			memcpy(&pid, dec + ((i * AEM_MAXPROCESSES + j) * 4), 4);
			if (pid != 0) printf("%c/%d=%u\n", numToChar(i), j, pid);
		}
	}

	close(sock);
	return EXIT_SUCCESS;
}
