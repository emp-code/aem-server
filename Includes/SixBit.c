#define _GNU_SOURCE // for memmem

#include <stdbool.h>
#include <string.h>
#include <ctype.h> // for islower/isdigit
#include <math.h> // for floor

#include <stdio.h>

#include "SixBit.h"

#define BIT_SET(a,b) ((a) |= (1ULL<<(b)))
#define BIT_CHECK(a,b) (!!((a) & (1ULL<<(b)))) // '!!' to make sure this returns 0 or 1

// Unused characters are used for Shield addresses
#define AEM_SIXBIT_CHAR_MIN_VALID 25
#define AEM_SIXBIT_CHAR_INVALID 0
#define AEM_SIXBIT_CHAR_HYPHEN 25
#define AEM_SIXBIT_CHAR_PERIOD 26
#define AEM_SIXBIT_CHAR_0 27
#define AEM_SIXBIT_CHAR_1 28
#define AEM_SIXBIT_CHAR_2 29
#define AEM_SIXBIT_CHAR_3 30
#define AEM_SIXBIT_CHAR_4 31
#define AEM_SIXBIT_CHAR_5 32
#define AEM_SIXBIT_CHAR_6 33
#define AEM_SIXBIT_CHAR_7 34
#define AEM_SIXBIT_CHAR_8 35
#define AEM_SIXBIT_CHAR_9 36
#define AEM_SIXBIT_CHAR_a 37
#define AEM_SIXBIT_CHAR_b 38
#define AEM_SIXBIT_CHAR_c 39
#define AEM_SIXBIT_CHAR_d 40
#define AEM_SIXBIT_CHAR_e 41
#define AEM_SIXBIT_CHAR_f 42
#define AEM_SIXBIT_CHAR_g 43
#define AEM_SIXBIT_CHAR_h 44
#define AEM_SIXBIT_CHAR_i 45
#define AEM_SIXBIT_CHAR_j 46
#define AEM_SIXBIT_CHAR_k 47
#define AEM_SIXBIT_CHAR_l 48
#define AEM_SIXBIT_CHAR_m 49
#define AEM_SIXBIT_CHAR_n 50
#define AEM_SIXBIT_CHAR_o 51
#define AEM_SIXBIT_CHAR_p 52
#define AEM_SIXBIT_CHAR_q 53
#define AEM_SIXBIT_CHAR_r 54
#define AEM_SIXBIT_CHAR_s 55
#define AEM_SIXBIT_CHAR_t 56
#define AEM_SIXBIT_CHAR_u 57
#define AEM_SIXBIT_CHAR_v 58
#define AEM_SIXBIT_CHAR_w 59
#define AEM_SIXBIT_CHAR_x 60
#define AEM_SIXBIT_CHAR_y 61
#define AEM_SIXBIT_CHAR_z 62
#define AEM_SIXBIT_CHAR_NULL 63

static int getBit(const unsigned char *c, const int bitNum) {
	const int skipBytes = floor(bitNum / (double)8);
	const int skipBits = bitNum % 8;

	return BIT_CHECK(c[skipBytes], skipBits);
}

static void setBit(unsigned char * const c, const int bitNum) {
	const int skipBytes = floor(bitNum / (double)8);
	const int skipBits = bitNum % 8;

	BIT_SET(c[skipBytes], skipBits);
}

static int charToUint6(const char character) {
	switch (character) {
		case '-': return AEM_SIXBIT_CHAR_HYPHEN;
		case '.': return AEM_SIXBIT_CHAR_PERIOD;
		case '0': return AEM_SIXBIT_CHAR_0;
		case '1': return AEM_SIXBIT_CHAR_1;
		case '2': return AEM_SIXBIT_CHAR_2;
		case '3': return AEM_SIXBIT_CHAR_3;
		case '4': return AEM_SIXBIT_CHAR_4;
		case '5': return AEM_SIXBIT_CHAR_5;
		case '6': return AEM_SIXBIT_CHAR_6;
		case '7': return AEM_SIXBIT_CHAR_7;
		case '8': return AEM_SIXBIT_CHAR_8;
		case '9': return AEM_SIXBIT_CHAR_9;
		case 'a': return AEM_SIXBIT_CHAR_a;
		case 'b': return AEM_SIXBIT_CHAR_b;
		case 'c': return AEM_SIXBIT_CHAR_c;
		case 'd': return AEM_SIXBIT_CHAR_d;
		case 'e': return AEM_SIXBIT_CHAR_e;
		case 'f': return AEM_SIXBIT_CHAR_f;
		case 'g': return AEM_SIXBIT_CHAR_g;
		case 'h': return AEM_SIXBIT_CHAR_h;
		case 'i': return AEM_SIXBIT_CHAR_i;
		case 'j': return AEM_SIXBIT_CHAR_j;
		case 'k': return AEM_SIXBIT_CHAR_k;
		case 'l': return AEM_SIXBIT_CHAR_l;
		case 'm': return AEM_SIXBIT_CHAR_m;
		case 'n': return AEM_SIXBIT_CHAR_n;
		case 'o': return AEM_SIXBIT_CHAR_o;
		case 'p': return AEM_SIXBIT_CHAR_p;
		case 'q': return AEM_SIXBIT_CHAR_q;
		case 'r': return AEM_SIXBIT_CHAR_r;
		case 's': return AEM_SIXBIT_CHAR_s;
		case 't': return AEM_SIXBIT_CHAR_t;
		case 'u': return AEM_SIXBIT_CHAR_u;
		case 'v': return AEM_SIXBIT_CHAR_v;
		case 'w': return AEM_SIXBIT_CHAR_w;
		case 'x': return AEM_SIXBIT_CHAR_x;
		case 'y': return AEM_SIXBIT_CHAR_y;
		case 'z': return AEM_SIXBIT_CHAR_z;
		case '\0': return AEM_SIXBIT_CHAR_NULL;

		default: return AEM_SIXBIT_CHAR_INVALID;
	}
}

static int addrToSixBit(const char * const source, const size_t lenSource, unsigned char * const out) {
	bzero(out, 18);

	for (size_t i = 0; i < 24; i++) {
		const int bitsDone = (i * 6);

		int num;
		if (i < lenSource) {
			num = charToUint6(source[i]);
		} else {
			num = AEM_SIXBIT_CHAR_NULL;
		}

		if (num >= 32) {setBit(out, bitsDone + 5); num -= 32;}
		if (num >= 16) {setBit(out, bitsDone + 4); num -= 16;}
		if (num >=  8) {setBit(out, bitsDone + 3); num -=  8;}
		if (num >=  4) {setBit(out, bitsDone + 2); num -=  4;}
		if (num >=  2) {setBit(out, bitsDone + 1); num -=  2;}
		if (num ==  1) {setBit(out, bitsDone + 0); num -=  1;}
	}

	return 1;
}

// Source must be 18 bytes
bool isNormalBinAddress(const unsigned char * const source) {
	int lastCharacter = 0;

	for (int i = 0; i < 24; i++) {
		int character = 0;
		if (getBit(source, i * 6 + 5)) character += 32;
		if (getBit(source, i * 6 + 4)) character += 16;
		if (getBit(source, i * 6 + 3)) character +=  8;
		if (getBit(source, i * 6 + 2)) character +=  4;
		if (getBit(source, i * 6 + 1)) character +=  2;
		if (getBit(source, i * 6 + 0)) character +=  1;

		// Only null after first null
		if (lastCharacter == AEM_SIXBIT_CHAR_NULL && character != AEM_SIXBIT_CHAR_NULL) return false;

		// No hyphen or period at end or beginning
		if ((i == 0 || i == 23) && (character == AEM_SIXBIT_CHAR_HYPHEN || character == AEM_SIXBIT_CHAR_PERIOD)) return false;

		// No consecutive hyphen/period
		if (character == AEM_SIXBIT_CHAR_HYPHEN && lastCharacter == AEM_SIXBIT_CHAR_HYPHEN) return false;
		if (character == AEM_SIXBIT_CHAR_HYPHEN && lastCharacter == AEM_SIXBIT_CHAR_PERIOD) return false;
		if (character == AEM_SIXBIT_CHAR_PERIOD && lastCharacter == AEM_SIXBIT_CHAR_HYPHEN) return false;
		if (character == AEM_SIXBIT_CHAR_PERIOD && lastCharacter == AEM_SIXBIT_CHAR_PERIOD) return false;

		if (character < AEM_SIXBIT_CHAR_MIN_VALID) return false; // No invalid characters
	}

	return true;
}

static bool isNormalAddress(const char * const source, const size_t lenSource) {
	if (lenSource < 1 || lenSource > 24) return false;

	// Only null after first null
	const char * const end = memchr(source, lenSource, '\0');
	if (end != NULL && end != source + lenSource) return false;

	// No hyphen or period at end or beginning
	if (source[0] == '-') return false;
	if (source[0] == '.') return false;
	if (source[lenSource - 1] == '-') return false;
	if (source[lenSource - 1] == '.') return false;

	// No consecutive hyphen/period
	if (memmem(source, lenSource, "--", 2) != NULL) return false;
	if (memmem(source, lenSource, "-.", 2) != NULL) return false;
	if (memmem(source, lenSource, ".-", 2) != NULL) return false;
	if (memmem(source, lenSource, "..", 2) != NULL) return false;

	for (size_t i = 0; i < lenSource; i++) {
		if (source[i] != '-' && source[i] != '.' && !islower(source[i]) && !isdigit(source[i])) return false; // No invalid characters
	}

	return true;
}

static int getHexValue(const char c) {
	for (int i = 0; i < 16; i++) {
		if (c == AEM_ADDRESS_HEXCHARS[i]) return i;
	}

	return -1;
}

int addr2bin(const char * const source, const size_t lenSource, unsigned char * const target) {
	if (source == NULL || lenSource < 1) return 0;

	if (isNormalAddress(source, lenSource)) return addrToSixBit(source, lenSource, target);

	if (lenSource != 36) return 0;

	// Shield address
	for (int i = 0; i < 18; i++) {
		const int one = getHexValue(source[i * 2]);
		if (one < 0) return 0;

		const int two = getHexValue(source[i * 2 + 1])  * 16;
		if (two < 0) return 0;

		target[i] = one + two;
	}

	return 1;
}
