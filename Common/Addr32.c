/* Addr32: a 5-bit text encoding designed for All-Ears Mail addresses.

	Supports [0-9a-z] with the following exceptions:
		- The letters i,l are treated as the digit 1
		- The letter o is treated as the digit 0
		- The letter v is treated as the letter w

	Stores 23 characters in 15 bytes.
*/

#include <stdbool.h>
#include <strings.h>
#include <stdio.h>

#include "Addr32.h"

#define ADDR32_CHAR_0 '0'
#define ADDR32_CHAR_1 '1'
#define ADDR32_CHAR_2 '2'
#define ADDR32_CHAR_3 '3'
#define ADDR32_CHAR_4 '4'
#define ADDR32_CHAR_5 '5'
#define ADDR32_CHAR_6 '6'
#define ADDR32_CHAR_7 '7'
#define ADDR32_CHAR_8 '8'
#define ADDR32_CHAR_9 '9'
#define ADDR32_CHAR_10 'a'
#define ADDR32_CHAR_11 'b'
#define ADDR32_CHAR_12 'c'
#define ADDR32_CHAR_13 'd'
#define ADDR32_CHAR_14 'e'
#define ADDR32_CHAR_15 'f'
#define ADDR32_CHAR_16 'g'
#define ADDR32_CHAR_17 'h'
#define ADDR32_CHAR_18 'j'
#define ADDR32_CHAR_19 'k'
#define ADDR32_CHAR_20 'm'
#define ADDR32_CHAR_21 'n'
#define ADDR32_CHAR_22 'p'
#define ADDR32_CHAR_23 'q'
#define ADDR32_CHAR_24 'r'
#define ADDR32_CHAR_25 's'
#define ADDR32_CHAR_26 't'
#define ADDR32_CHAR_27 'u'
#define ADDR32_CHAR_28 'w'
#define ADDR32_CHAR_29 'x'
#define ADDR32_CHAR_30 'y'
#define ADDR32_CHAR_31 'z'

static const char addr32_chars[] = {
ADDR32_CHAR_0,  ADDR32_CHAR_1,  ADDR32_CHAR_2,  ADDR32_CHAR_3,  ADDR32_CHAR_4,  ADDR32_CHAR_5,  ADDR32_CHAR_6,  ADDR32_CHAR_7,
ADDR32_CHAR_8,  ADDR32_CHAR_9,  ADDR32_CHAR_10, ADDR32_CHAR_11, ADDR32_CHAR_12, ADDR32_CHAR_13, ADDR32_CHAR_14, ADDR32_CHAR_15,
ADDR32_CHAR_16, ADDR32_CHAR_17, ADDR32_CHAR_18, ADDR32_CHAR_19, ADDR32_CHAR_20, ADDR32_CHAR_21, ADDR32_CHAR_22, ADDR32_CHAR_23,
ADDR32_CHAR_24, ADDR32_CHAR_25, ADDR32_CHAR_26, ADDR32_CHAR_27, ADDR32_CHAR_28, ADDR32_CHAR_29, ADDR32_CHAR_30, ADDR32_CHAR_31
};

__attribute__((warn_unused_result, const))
static int charToUint5(const char character) {
	switch (character) {
		case ADDR32_CHAR_0: return 0;
		case ADDR32_CHAR_1: return 1;
		case ADDR32_CHAR_2: return 2;
		case ADDR32_CHAR_3: return 3;
		case ADDR32_CHAR_4: return 4;
		case ADDR32_CHAR_5: return 5;
		case ADDR32_CHAR_6: return 6;
		case ADDR32_CHAR_7: return 7;
		case ADDR32_CHAR_8: return 8;
		case ADDR32_CHAR_9: return 9;
		case ADDR32_CHAR_10: return 10;
		case ADDR32_CHAR_11: return 11;
		case ADDR32_CHAR_12: return 12;
		case ADDR32_CHAR_13: return 13;
		case ADDR32_CHAR_14: return 14;
		case ADDR32_CHAR_15: return 15;
		case ADDR32_CHAR_16: return 16;
		case ADDR32_CHAR_17: return 17;
		case ADDR32_CHAR_18: return 18;
		case ADDR32_CHAR_19: return 19;
		case ADDR32_CHAR_20: return 20;
		case ADDR32_CHAR_21: return 21;
		case ADDR32_CHAR_22: return 22;
		case ADDR32_CHAR_23: return 23;
		case ADDR32_CHAR_24: return 24;
		case ADDR32_CHAR_25: return 25;
		case ADDR32_CHAR_26: return 26;
		case ADDR32_CHAR_27: return 27;
		case ADDR32_CHAR_28: return 28;
		case ADDR32_CHAR_29: return 29;
		case ADDR32_CHAR_30: return 30;
		case ADDR32_CHAR_31: return 31;

		case 'o': return 0;

		case 'i':
		case 'l': return 1;

		case 'v': return 28;

		default: return -1;
	}
}

static void setBit(unsigned char *target, int * const bit, int * const byte, const bool setOn) {
	if (setOn) target[*byte] |= (1 << (7 - *bit));

	(*bit)++;
	if (*bit > 7) {
		(*byte)++;
		*bit = 0;
	}
}

// Unused
/*
__attribute__((warn_unused_result))
static bool getBit(const unsigned char * const src, int * const bit, int * const byte) {
	const bool result = (1 & (src[*byte] >> (7 - *bit)));

	(*bit)++;
	if (*bit > 7) {
		(*byte)++;
		*bit = 0;
	}

	return result;
}
*/

// out must be 15 bytes
void addr32_store(unsigned char * const out, const char * const src, size_t len) {
	if (len > 24) return;

	bzero(out, 15);

	if (len < 24)
		out[0] = len << 3; // Normal address: First five bits store length
	else
		len = 23; // Shield address: Ignore last character

	int bit = 5;
	int byte = 0;

	for (size_t i = 0; i < len; i++) {
		int num = charToUint5(src[i]);

		if (num < 0) {
			bzero(out, 15);
			return;
		}

		setBit(out, &bit, &byte, (num >= 16)); if (num >= 16) num -= 16;
		setBit(out, &bit, &byte, (num >=  8)); if (num >=  8) num -=  8;
		setBit(out, &bit, &byte, (num >=  4)); if (num >=  4) num -=  4;
		setBit(out, &bit, &byte, (num >=  2)); if (num >=  2) num -=  2;
		setBit(out, &bit, &byte, (num >=  1));
	}
}

// Unused, not updated
/*
// bin must be 15 bytes; out must be 24 bytes
void addr32_fetch(char * const out, const unsigned char * const bin) {
	int bit = 0;
	int byte = 0;

	bool shield = false;

	for (int i = 0; i < 24; i++) {
		int num = 0;
		if (getBit(bin, &bit, &byte)) num += 16;
		if (getBit(bin, &bit, &byte)) num +=  8;
		if (getBit(bin, &bit, &byte)) num +=  4;
		if (getBit(bin, &bit, &byte)) num +=  2;
		if (getBit(bin, &bit, &byte)) num +=  1;

		if (i == 0 && num == 0) shield = true;

		out[i] = shield ? shld32_chars[num] : addr32_chars[num];
	}

	if (shield) {
		out[0] = out[23];
		out[23] = shld32_chars[0];
	}
}
*/
