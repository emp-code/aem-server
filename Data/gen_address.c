// Warning: Slow and resource-intensive (Argon2)

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h> // for open

#include <sodium.h>

#include "../Common/Addr32.c"

#include "../Global.h"

static unsigned char salt_normal[AEM_LEN_SLT_NRM];

static uint64_t addressToHash(const unsigned char * const addr32) {
	if (addr32 == NULL) return -1;

	uint64_t halves[2];
	if (crypto_pwhash((unsigned char*)halves, 16, (const char*)addr32, 10, salt_normal, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) return 0;

	return halves[0] ^ halves[1];
}

int main(void) {
	if (sodium_init() < 0) {puts("Terminating: Failed sodium_init()"); return EXIT_FAILURE;}

	puts("#ifndef AEM_DATA_ADDRESS_H");
	puts("#define AEM_DATA_ADDRESS_H");
	puts("");

	randombytes_buf(salt_normal, AEM_LEN_SLT_NRM);
	printf("#define AEM_SLT_NRM (const unsigned char[]) {");
	for (unsigned int i = 0; i < AEM_LEN_SLT_NRM; i++) {
		printf("'\\x%.2x'", salt_normal[i]);

		if (i < AEM_LEN_SLT_NRM - 1)
			printf(", ");
	}
	puts("}\n");

	printf("#define AEM_HASH_PUBLIC %lullu\n",   addressToHash(AEM_ADDR32_PUBLIC));
	printf("#define AEM_HASH_SYSTEM %lullu\n\n", addressToHash(AEM_ADDR32_SYSTEM));
	sodium_memzero(salt_normal, AEM_LEN_SLT_NRM);

	const int fdTxt = open("Admin.adr.txt", O_RDONLY);
	if (fdTxt < 0) {puts("Failed to open Admin.adr.txt"); return EXIT_FAILURE;}

	const off_t len = lseek(fdTxt, 0, SEEK_END);
	if (len < 0) {puts("Failed to read Admin.adr.txt"); return EXIT_FAILURE;}
	unsigned char data[len];
	if (pread(fdTxt, data, len, 0) != len) {puts("Failed read"); return EXIT_FAILURE;}

	unsigned int lineCount = 0;
	for (off_t i = 0; i < len; i++) {
		if (data[i] == '\n') lineCount++;
	}

	printf("#define AEM_HASH_ADMIN_COUNT %ullu\n#define AEM_HASH_ADMIN (const uint64_t[]) { \\", lineCount);

	unsigned char *s = data;
	for (unsigned int i = 0; i < lineCount; i++) {
		unsigned char *lf = memchr(s, '\n', (data + len) - s);
		if (lf == NULL) break;

		const size_t lenSrc = lf - s;
		if (lenSrc > 15) {
			printf("\n/* Rejected, too long: %.*s */ \\\n", (int)lenSrc, s);
			s = lf + 1;
			continue;
		}

		unsigned char addr32[10];
		addr32_store(addr32, (char*)s, lenSrc);
		printf("\n%lullu", addressToHash(addr32));
		if (i < lineCount - 1) printf(",\\");

		s = lf + 1;
	}

	puts("\\\n}\n\n#endif");

	close(fdTxt);

	return 0;
}
