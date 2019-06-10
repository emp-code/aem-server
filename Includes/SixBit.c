#include <stdlib.h>
#include <strings.h>
#include <math.h>

#define BIT_SET(a,b) ((a) |= (1ULL<<(b)))
#define BIT_CHECK(a,b) (!!((a) & (1ULL<<(b)))) // '!!' to make sure this returns 0 or 1

static int charToUint6(const char character) {
	switch (character) {
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'a': return 10;
		case 'b': return 11;
		case 'c': return 12;
		case 'd': return 13;
		case 'e': return 14;
		case 'f': return 15;
		case 'g': return 16;
		case 'h': return 17;
		case 'i': return 18;
		case 'j': return 19;
		case 'k': return 20;
		case 'l': return 21;
		case 'm': return 22;
		case 'n': return 23;
		case 'o': return 24;
		case 'p': return 25;
		case 'q': return 26;
		case 'r': return 27;
		case 's': return 28;
		case 't': return 29;
		case 'u': return 30;
		case 'v': return 31;
		case 'w': return 32;
		case 'x': return 33;
		case 'y': return 34;
		case 'z': return 35;
		case '.': return 36;
		case '-': return 37;
		case '@': return 38;

		/*
			39..61 open
		*/

		// Terminating characters
		case '\0':
		case '|':
			return 62;

		default: return 63;
	}
}

static void setBit(char *c, const int bitNum) {
	const int skipBytes = floor(bitNum / (double)8);
	const int skipBits = bitNum % 8;

	BIT_SET(c[skipBytes], skipBits);
}

char *textToSixBit(const char *source, const size_t lenSource) {
	char *out = calloc(ceil(lenSource * 0.75), 1);

	for (int i = 0; i < lenSource; i++) {
		int num = charToUint6(source[i]);

		if (num >= 32) {setBit(out, (i * 6) + 5); num -= 32;}
		if (num >= 16) {setBit(out, (i * 6) + 4); num -= 16;}
		if (num >=  8) {setBit(out, (i * 6) + 3); num -=  8;}
		if (num >=  4) {setBit(out, (i * 6) + 2); num -=  4;}
		if (num >=  2) {setBit(out, (i * 6) + 1); num -=  2;}
		if (num ==  1) {setBit(out, (i * 6) + 0); num -=  1;}
	}

	return out;
}

static int getBit(const char *c, const int bitNum) {
	const int skipBytes = floor(bitNum / (double)8);
	const int skipBits = bitNum % 8;

	return BIT_CHECK(c[skipBytes], skipBits);
}

char *sixBitToText(const char *source, const size_t lenSource) {
	const size_t lenOut = lenSource * ((double)8 / 6);
	char *out = malloc(lenOut + 1);

	const char *charTable = "0123456789abcdefghijklmnopqrstuvwxyz.-@???????????????????????\0!";

	for (int i = 0; i < lenOut; i++) {
		int num = 0;

		if (getBit(source, (i * 6) + 5)) num += 32;
		if (getBit(source, (i * 6) + 4)) num += 16;
		if (getBit(source, (i * 6) + 3)) num +=  8;
		if (getBit(source, (i * 6) + 2)) num +=  4;
		if (getBit(source, (i * 6) + 1)) num +=  2;
		if (getBit(source, (i * 6) + 0)) num +=  1;

		out[i] = charTable[num];
	}

	out[lenOut] = '\0';
	return out;
}
