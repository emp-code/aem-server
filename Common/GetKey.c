#include <ctype.h> // for isxdigit
#include <stdio.h>

#include <sodium.h>

#include "../Common/AEM_KDF.h"
#include "../Common/ToggleEcho.h"

#include "GetKey.h"

int getKey(unsigned char * const key) {
	toggleEcho(false);
#ifdef AEM_MANAGER
	fprintf(stderr, "Enter the Manager Protocol Key (MPK) in hex - will not echo\n");

	char keyHex[AEM_KDF_MPK_KEYLEN * 2];
	for (unsigned int i = 0; i < AEM_KDF_MPK_KEYLEN * 2; i++) {
		const int gc = getchar_unlocked();
		if (gc == EOF || !isxdigit(gc)) {toggleEcho(true); return -1;}
		keyHex[i] = gc;
	}

	sodium_hex2bin(key, AEM_KDF_MPK_KEYLEN, keyHex, AEM_KDF_MPK_KEYLEN * 2, NULL, NULL, NULL);
	sodium_memzero(keyHex, AEM_KDF_MPK_KEYLEN * 2);
#else
	fprintf(stderr, "Enter the Server Master Key (SMK) in hex - will not echo\n");

	char keyHex[AEM_KDF_SMK_KEYLEN * 2];
	for (unsigned int i = 0; i < AEM_KDF_SMK_KEYLEN * 2; i++) {
		const int gc = getchar_unlocked();
		if (gc == EOF || !isxdigit(gc)) {toggleEcho(true); return -1;}
		keyHex[i] = gc;
	}

	sodium_hex2bin(key, AEM_KDF_SMK_KEYLEN, keyHex, AEM_KDF_SMK_KEYLEN * 2, NULL, NULL, NULL);
	sodium_memzero(keyHex, AEM_KDF_SMK_KEYLEN * 2);
#endif
	toggleEcho(true);
	return 0;
}
