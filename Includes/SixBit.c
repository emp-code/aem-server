#include <stdlib.h>
#include <strings.h>
#include <math.h>

#define BIT_SET(a,b) ((a) |= (1ULL<<(b)))
#define BIT_CHECK(a,b) (!!((a) & (1ULL<<(b)))) // '!!' to make sure this returns 0 or 1

static int charToUint6(const char character) {
	switch (character) {
		case '|': return 0;
		case '0': return 1;
		case '1': return 2;
		case '2': return 3;
		case '3': return 4;
		case '4': return 5;
		case '5': return 6;
		case '6': return 7;
		case '7': return 8;
		case '8': return 9;
		case '9': return 10;
		case 'a': return 11;
		case 'b': return 12;
		case 'c': return 13;
		case 'd': return 14;
		case 'e': return 15;
		case 'f': return 16;
		case 'g': return 17;
		case 'h': return 18;
		case 'i': return 19;
		case 'j': return 20;
		case 'k': return 21;
		case 'l': return 22;
		case 'm': return 23;
		case 'n': return 24;
		case 'o': return 25;
		case 'p': return 26;
		case 'q': return 27;
		case 'r': return 28;
		case 's': return 29;
		case 't': return 30;
		case 'u': return 31;
		case 'v': return 32;
		case 'w': return 33;
		case 'x': return 34;
		case 'y': return 35;
		case 'z': return 36;
		case '.': return 37;
		case '-': return 38;
		case '@': return 39;

		/*
			40..63 open
		*/

		default: return 0;
	}
}

static void setBit(unsigned char *c, const int bitNum) {
	const int skipBytes = floor(bitNum / (double)8);
	const int skipBits = bitNum % 8;

	BIT_SET(c[skipBytes], skipBits);
}

unsigned char *textToSixBit(const char *source, const size_t lenSource) {
	if (lenSource > 24) return NULL;
	unsigned char *out = calloc(18, 1);//calloc(ceil(lenSource * 0.75), 1);
	if (out == NULL) return NULL;

	for (size_t i = 0; i < lenSource; i++) {
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

	const char *charTable = "|0123456789abcdefghijklmnopqrstuvwxyz.-@????????????????????????";

	for (size_t i = 0; i < lenOut; i++) {
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
