#include <fcntl.h> // for open
#include <stdio.h>
#include <string.h>
#include <unistd.h> // for write

#include <sodium.h>

#include "../Global.h"
#include "../Common/GetKey.h"

int main(int argc, char *argv[]) {
	puts("DataCrypt: Encrypt additional files for All-Ears Mail");

	if (argc != 2) {printf("Usage: %s input.file\n", argv[0]); return EXIT_FAILURE;}
	if (sodium_init() < 0) {puts("Failed sodium_init()"); return EXIT_FAILURE;}

	// Read source file
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("Failed opening file");
		return EXIT_FAILURE;
	}

	const off_t lenClear = lseek(fd, 0, SEEK_END);
	if (lenClear > AEM_MAXLEN_DATAFILE) {
		puts("File too large");
		return EXIT_FAILURE;
	}

	unsigned char clear[lenClear];
	const off_t readBytes = pread(fd, clear, lenClear, 0);
	close(fd);

	if (readBytes != lenClear) {
		puts("Failed reading file");
		return EXIT_FAILURE;
	}

	// Get Launch Key
	unsigned char smk[AEM_KDF_MASTER_KEYLEN];
	if (getKey(smk) != 0) {puts("Failed reading key"); return EXIT_FAILURE;}

	unsigned char launchKey[crypto_aead_aegis256_KEYBYTES];
	aem_kdf_master(launchKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_SMK_LCH, smk);
	sodium_memzero(smk, AEM_KDF_MASTER_KEYLEN);

	// Encrypt
	const int lenEnc = crypto_aead_aegis256_NPUBBYTES + lenClear + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);

	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, clear, lenClear, NULL, 0, NULL, enc, launchKey);
	sodium_memzero(launchKey, crypto_aead_aegis256_KEYBYTES);

	// Copy to destination
	char pathEnc[27 + strlen(argv[1])];
	sprintf(pathEnc, "/var/lib/allears/Data/%s.enc", argv[1]);
	fd = open(pathEnc, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR);
	if (fd < 0) {
		perror("Failed creating file");
		return EXIT_FAILURE;
	}

	const int ret = write(fd, enc, lenEnc);

	if (ret != lenEnc) {
		perror("Failed writing file");
		close(fd);
		return EXIT_FAILURE;
	}

	close(fd);
	printf("Created %s\n", pathEnc);
	return EXIT_SUCCESS;
}
