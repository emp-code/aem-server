// BinCrypt.c: Encrypt All-Ears Mail binaries

#include <fcntl.h> // for open
#include <stdio.h>
#include <string.h>
#include <unistd.h> // for write

#include <sodium.h>

#include "../Global.h"
#include "../Common/GetKey.h"

int main(int argc, char *argv[]) {
	puts("BinCrypt: Encrypt All-Ears Mail binaries");

	if (argc != 2) {printf("Usage: %s input.file\n", argv[0]); return EXIT_FAILURE;}
	if (sodium_init() < 0) {puts("Failed sodium_init()"); return EXIT_FAILURE;}

	unsigned char smk[AEM_KDF_KEYSIZE];
	if (getKey(smk) != 0) {puts("Failed reading key"); return EXIT_FAILURE;}

	unsigned char binKey[crypto_aead_aegis256_KEYBYTES];
	aem_kdf(binKey, crypto_aead_aegis256_KEYBYTES, AEM_KDF_KEYID_SMK_BIN, smk);
	sodium_memzero(smk, crypto_kdf_KEYBYTES);

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		sodium_memzero(binKey, crypto_aead_aegis256_KEYBYTES);
		perror("Failed opening file");
		return EXIT_FAILURE;
	}

	const off_t lenClear = lseek(fd, 0, SEEK_END);
	if (lenClear > AEM_MAXSIZE_EXEC) {
		puts("File too large");
		return EXIT_FAILURE;
	}

	unsigned char clear[lenClear];
	const off_t readBytes = pread(fd, clear, lenClear, 0);
	close(fd);

	if (readBytes != lenClear) {
		sodium_memzero(binKey, crypto_aead_aegis256_KEYBYTES);
		puts("Failed reading file");
		return EXIT_FAILURE;
	}

	const int lenEnc = crypto_aead_aegis256_NPUBBYTES + lenClear + crypto_aead_aegis256_ABYTES;
	unsigned char enc[lenEnc];
	randombytes_buf(enc, crypto_aead_aegis256_NPUBBYTES);

	crypto_aead_aegis256_encrypt(enc + crypto_aead_aegis256_NPUBBYTES, NULL, clear, lenClear, NULL, 0, NULL, enc, binKey);
	sodium_memzero(binKey, crypto_aead_aegis256_KEYBYTES);

	char pathEnc[22 + strlen(argv[1])];
	sprintf(pathEnc, "/var/lib/allears/bin/%s", argv[1]);
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
