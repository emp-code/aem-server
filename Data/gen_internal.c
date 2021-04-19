#include <stdio.h>
#include <sodium.h>

static void printKey(const char * const def, const size_t len) {
	unsigned char buf[len];
	randombytes_buf(buf, len);

	printf("#define %s (const unsigned char[]) {", def);

	for (size_t i = 0; i < len; i++) {
		printf("'\\x%.2x'", buf[i]);
		if (i < (len - 1)) printf(",");
	}

	sodium_memzero(buf, len);
	puts("}");
}

static void printAbstract(const char * const def) {
	char buf[107];
	randombytes_buf(buf, 107);

	printf("#define %s (const char[]) {0,", def);

	for (size_t i = 0; i < 107; i++) {
		printf("%d", buf[i]);
		if (i < 106) printf(",");
	}

	sodium_memzero(buf, 107);
	puts("}");
}

static void printIds(void) {
	uint8_t idAcc = 0;
	uint8_t idApi = 0;
	uint8_t idMta = 0;
	while (idAcc == 0) idAcc = randombytes_uniform(UINT8_MAX);
	while (idApi == 0 || idApi == idAcc) idApi = randombytes_uniform(UINT8_MAX);
	while (idMta == 0 || idMta == idAcc || idMta == idApi) idMta = randombytes_uniform(UINT8_MAX);

	puts("#define AEM_IDENTIFIER_INV 0x00");
	printf("#define AEM_IDENTIFIER_ACC 0x%.2X\n", idAcc);
	printf("#define AEM_IDENTIFIER_API 0x%.2X\n", idApi);
	printf("#define AEM_IDENTIFIER_MTA 0x%.2X\n", idMta);
}

int main(void) {
	if (sodium_init() < 0) {puts("Terminating: Failed sodium_init()"); return EXIT_FAILURE;}

	puts("#ifndef AEM_DATA_INTERNAL_H");
	puts("#define AEM_DATA_INTERNAL_H");
	puts("");

	printIds();
	puts("");

	printKey("AEM_KEY_ACCESS_ACCOUNT_API", crypto_box_SECRETKEYBYTES);
	printKey("AEM_KEY_ACCESS_ACCOUNT_MTA", crypto_box_SECRETKEYBYTES);
	printKey("AEM_KEY_ACCESS_ENQUIRY_API", crypto_box_SECRETKEYBYTES);
	printKey("AEM_KEY_ACCESS_ENQUIRY_MTA", crypto_box_SECRETKEYBYTES);
	printKey("AEM_KEY_ACCESS_STORAGE_ACC", crypto_box_SECRETKEYBYTES);
	printKey("AEM_KEY_ACCESS_STORAGE_API", crypto_box_SECRETKEYBYTES);
	printKey("AEM_KEY_ACCESS_STORAGE_MTA", crypto_box_SECRETKEYBYTES);

	puts("");

	puts("#define AEM_SOCKPATH_LEN 108");
	printAbstract("AEM_SOCKPATH_ACCOUNT");
	printAbstract("AEM_SOCKPATH_ENQUIRY");
	printAbstract("AEM_SOCKPATH_STORAGE");

	puts("");
	puts("#endif");

	return 0;
}
