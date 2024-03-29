#include <ctype.h> // for isxdigit
#include <stdio.h>

#include <sodium.h>

#include "../Common/ToggleEcho.h"

#include "GetKey.h"

int getKey(unsigned char * const master) {
	toggleEcho(false);
	fprintf(stderr, "Enter Master Key (hex) - will not echo\n");

	char masterHex[crypto_secretbox_KEYBYTES * 2];
	for (unsigned int i = 0; i < crypto_secretbox_KEYBYTES * 2; i++) {
		const int gc = getchar_unlocked();
		if (gc == EOF || !isxdigit(gc)) {toggleEcho(true); return -1;}
		masterHex[i] = gc;
	}

	toggleEcho(true);

	sodium_hex2bin(master, crypto_secretbox_KEYBYTES, masterHex, crypto_secretbox_KEYBYTES * 2, NULL, NULL, NULL);
	sodium_memzero(masterHex, crypto_secretbox_KEYBYTES * 2);
	return 0;
}
