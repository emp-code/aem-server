/* Addr32: a 5-bit text encoding designed for All-Ears Mail addresses.

	Supports [0-9a-z] with the following exceptions:
		- The letters i,l are treated as the digit 1
		- The letter o is treated as the digit 0
		- The letter v is treated as the letter w

	Stores 16 characters (or length + 15) in 10 bytes
*/

#include "Addr32.h"

static unsigned char charToAddr32(const unsigned char src) {
	switch (src) {
		case '0':
		case 'O':
		case 'o': return 0;

		case '1':
		case 'I':
		case 'i':
		case 'L': 
		case 'l': return 1;

		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;

		case 'A':
		case 'a': return 10;
		case 'B':
		case 'b': return 11;
		case 'C':
		case 'c': return 12;
		case 'D':
		case 'd': return 13;
		case 'E':
		case 'e': return 14;
		case 'F':
		case 'f': return 15;
		case 'G':
		case 'g': return 16;
		case 'H':
		case 'h': return 17;
		case 'J':
		case 'j': return 18;
		case 'K':
		case 'k': return 19;
		case 'M':
		case 'm': return 20;
		case 'N':
		case 'n': return 21;
		case 'P':
		case 'p': return 22;
		case 'Q':
		case 'q': return 23;
		case 'R':
		case 'r': return 24;
		case 'S':
		case 's': return 25;
		case 'T':
		case 't': return 26;
		case 'U':
		case 'u': return 27;

		case 'V':
		case 'v':
		case 'W':
		case 'w': return 28;

		case 'X':
		case 'x': return 29;
		case 'Y':
		case 'y': return 30;
		case 'Z':
		case 'z': return 31;
	}

	return 0xFF;
}

void addr32_store(unsigned char out[10], const unsigned char * const original, int lenOriginal) {
	unsigned char src[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int lenSrc = 0;

	for (int i = 0; i < lenOriginal; i++) {
		src[lenSrc] = charToAddr32(original[i]);
		if (src[lenSrc] != 0xFF) lenSrc++;
		if (lenSrc == 16) break;
	}

	out[0] = ((lenSrc == 16) ? (128 | (src[15] << 3)) : (lenSrc << 3)) | (src[0] >> 2);

	out[1] = (src[0]  << 6) | (src[1]  << 1) | (src[2] >> 4);
	out[2] = (src[2]  << 4) | (src[3]  >> 1);
	out[3] = (src[3]  << 7) | (src[4]  << 2) | (src[5] >> 3);
	out[4] = (src[5]  << 5) |  src[6];

	out[5] = (src[7]  << 3) | (src[8]  >> 2);
	out[6] = (src[8]  << 6) | (src[9]  << 1) | (src[10] >> 4);
	out[7] = (src[10] << 4) | (src[11] >> 1);
	out[8] = (src[11] << 7) | (src[12] << 2) | (src[13] >> 3);
	out[9] = (src[13] << 5) |  src[14];
}
