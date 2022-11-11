#include <stdio.h>
#include <sodium.h>

static void printKey(const char * const def, const size_t len) {
	printf("#define %s (const unsigned char[]) {", def);

	unsigned char buf[len];
	randombytes_buf(buf, len);

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

int main(void) {
	if (sodium_init() < 0) {fputs("Terminating: Failed sodium_init()", stderr); return EXIT_FAILURE;}

	puts("#ifndef AEM_DATA_INTERNAL_H");
	puts("#define AEM_DATA_INTERNAL_H");
	puts("");

	printKey("AEM_KEY_INTCOM_NULL", crypto_secretbox_KEYBYTES);
	printKey("AEM_KEY_INTCOM_ACCOUNT_API", crypto_secretbox_KEYBYTES);
	printKey("AEM_KEY_INTCOM_ACCOUNT_MTA", crypto_secretbox_KEYBYTES);
	printKey("AEM_KEY_INTCOM_ENQUIRY_API", crypto_secretbox_KEYBYTES);
	printKey("AEM_KEY_INTCOM_ENQUIRY_MTA", crypto_secretbox_KEYBYTES);
	printKey("AEM_KEY_INTCOM_STORAGE_ACC", crypto_secretbox_KEYBYTES);
	printKey("AEM_KEY_INTCOM_STORAGE_API", crypto_secretbox_KEYBYTES);
	printKey("AEM_KEY_INTCOM_STORAGE_DLV", crypto_secretbox_KEYBYTES);
	printKey("AEM_KEY_INTCOM_STREAM", crypto_secretstream_xchacha20poly1305_KEYBYTES); // MTA->Deliver
	puts("");

	puts("#define AEM_SOCKPATH_LEN 108");
	printAbstract("AEM_SOCKPATH_ACCOUNT");
	printAbstract("AEM_SOCKPATH_DELIVER");
	printAbstract("AEM_SOCKPATH_ENQUIRY");
	printAbstract("AEM_SOCKPATH_STORAGE");
	puts("");

	puts("#endif");

	return 0;
}
