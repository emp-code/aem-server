#include <ctype.h> // for isxdigit
#include <stdio.h>

#include <sodium.h>

#include "../Common/AEM_KDF.h" // For AEM_KDF_MASTER_KEYLEN
#include "../Common/ToggleEcho.h"

#include "GetKey.h"

int getKey(unsigned char * const master) {
	toggleEcho(false);
	fprintf(stderr, "Enter the Server Master Key (SMK) in hex - will not echo\n");

	char masterHex[AEM_KDF_MASTER_KEYLEN * 2];
	for (unsigned int i = 0; i < AEM_KDF_MASTER_KEYLEN * 2; i++) {
		const int gc = getchar_unlocked();
		if (gc == EOF || !isxdigit(gc)) {toggleEcho(true); return -1;}
		masterHex[i] = gc;
	}

	toggleEcho(true);

	sodium_hex2bin(master, AEM_KDF_MASTER_KEYLEN, masterHex, AEM_KDF_MASTER_KEYLEN * 2, NULL, NULL, NULL);
	sodium_memzero(masterHex, AEM_KDF_MASTER_KEYLEN * 2);
	return 0;
}
