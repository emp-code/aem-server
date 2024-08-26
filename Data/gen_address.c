#include <ctype.h>
#include <fcntl.h> // for open
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/AEM_KDF.h"
#include "../Common/Addr32.h"
#include "../Common/GetKey.h"

static unsigned char saltNormal[AEM_SALTNORMAL_LEN];

static uint64_t addressToHash(const unsigned char * const addr32) {
	if (addr32 == NULL) return 0;

#ifdef AEM_ADDRESS_NOPWHASH
	uint64_t hash;
	crypto_shorthash((unsigned char*)&hash, addr32, AEM_ADDR32_BINLEN, saltNormal);
	return hash;
#else
	uint64_t halves[2];
	if (crypto_pwhash((unsigned char*)halves, sizeof(uint64_t) * 2, (const char*)addr32, AEM_ADDR32_BINLEN, saltNormal, AEM_ADDRESS_ARGON2_OPSLIMIT, AEM_ADDRESS_ARGON2_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) != 0) {
		fputs("Failed hashing address", stderr);
		return 0;
	}
	return halves[0] ^ halves[1];
#endif
}

int main(int argc, char *argv[]) {
	if (argc != 2) {fprintf(stderr, "Usage: %s address-list.txt\n", argv[0]); return EXIT_FAILURE;}
	if (sodium_init() < 0) {fputs("Terminating: Failed sodium_init()", stderr); return EXIT_FAILURE;}

	// Determine the normal address salt
	unsigned char smk[AEM_KDF_MASTER_KEYLEN];
	if (getKey(smk) != 0) {fputs("Failed reading key", stderr); return -1;}

	unsigned char key_acc[AEM_KDF_SUB_KEYLEN];
	aem_kdf_master(key_acc, AEM_KDF_SUB_KEYLEN, AEM_KDF_KEYID_SMK_ACC, smk);
	aem_kdf_sub(saltNormal, AEM_SALTNORMAL_LEN, AEM_KDF_KEYID_ACC_NRM, key_acc);
	sodium_memzero(key_acc, AEM_KDF_SUB_KEYLEN);
	sodium_memzero(smk, AEM_KDF_MASTER_KEYLEN);

	// Print the header file
	puts("#ifndef AEM_DATA_ADDRESS_H");
	puts("#define AEM_DATA_ADDRESS_H");
	puts("");

	printf("#define AEM_ADDRHASH_SYSTEM %luLLU\n\n", addressToHash(AEM_ADDR32_SYSTEM));

	const int fdTxt = open(argv[1], O_RDONLY);
	if (fdTxt < 0) {fprintf(stderr, "Failed to open %s\n", argv[1]); return EXIT_FAILURE;}

	const off_t len = lseek(fdTxt, 0, SEEK_END);
	if (len < 0) {fprintf(stderr, "Failed to read %s\n", argv[1]); return EXIT_FAILURE;}
	unsigned char data[len];
	if (pread(fdTxt, data, len, 0) != len) {fputs("Failed read", stderr); return EXIT_FAILURE;}

	int lineCount = 0;
	for (off_t i = 0; i < len; i++) {
		if (data[i] == '\n') lineCount++;
	}

	printf("#define AEM_ADDRHASH_ADMIN (const uint64_t[]) { \\");

	int entries = 0;	
	const unsigned char *s = data;
	for (int i = 0; i < lineCount; i++) {
		const unsigned char * const lf = memchr(s, '\n', (data + len) - s);
		if (lf == NULL) break;

		const size_t lenSrc = lf - s;
		if (lenSrc < 16) {
			unsigned char addr32[10];
			addr32_store(addr32, s, lenSrc);
			printf("\n%luLLU", addressToHash(addr32));
			if (i < lineCount - 1) printf(",\\");
			entries++;
		} else {
			fprintf(stderr, "Rejected, too long: %.*s\n", (int)lenSrc, s);
		}

		s = lf + 1;
	}

	sodium_memzero(saltNormal, AEM_SALTNORMAL_LEN);

	puts("\\\n}\n");
	printf("#define AEM_ADDRHASH_ADMIN_COUNT %u\n", entries);
	puts("\n#endif");

	close(fdTxt);

	return 0;
}
