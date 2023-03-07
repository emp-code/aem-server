#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "../Global.h"
#include "../Common/Trim.h"
#include "../Common/ref2codepoint.h"

#include "HtmlRefs.h"

static size_t utf8char(unsigned char * const text, const unsigned int codepoint) {
	if (codepoint == 9 || codepoint == 10) { // Tab/Linefeed -> Space
		text[0] = ' ';
		return 1;
	}

	if (codepoint < 32 || codepoint == 127) return 0; // Control characters

	if (codepoint <= 0x007F) {
		text[0] = codepoint;
		return 1;
	}

	if (codepoint <= 0x07FF) { // 11 bits / 2 bytes
		text[0] = 192; // 110: 128,64,32
		if (codepoint & 1024) text[0] |= 16;
		if (codepoint &  512) text[0] |=  8;
		if (codepoint &  256) text[0] |=  4;
		if (codepoint &  128) text[0] |=  2;
		if (codepoint &   64) text[0] |=  1;

		text[1] = 128 | (codepoint & 63);

		return 2;
	}

	if (codepoint <= 0xFFFF) { // 16 bits / 3 bytes
		text[0] = 224; // 1110: 128,64,32,16
		if (codepoint & 32768) text[0] |= 8;
		if (codepoint & 16384) text[0] |= 4;
		if (codepoint &  8192) text[0] |= 2;
		if (codepoint &  4096) text[0] |= 1;

		text[1] = 128; // 10: 128,64
		if (codepoint & 2048) text[1] |= 32;
		if (codepoint & 1024) text[1] |= 16;
		if (codepoint &  512) text[1] |=  8;
		if (codepoint &  256) text[1] |=  4;
		if (codepoint &  128) text[1] |=  2;
		if (codepoint &   64) text[1] |=  1;

		text[2] = 128 | (codepoint & 63);

		return 3;
	}

	if (codepoint <= 0x10FFFF) { // 21 bits / 4 bytes
		text[0] = 240; // 1110: 128,64,32,16,8
		if (codepoint & 1048576) text[0] |= 4;
		if (codepoint &  524288) text[0] |= 2;
		if (codepoint &  262144) text[0] |= 1;

		text[1] = 128; // 10: 128,64
		if (codepoint & 131072) text[1] |= 32;
		if (codepoint &  65536) text[1] |= 16;
		if (codepoint &  32768) text[1] |=  8;
		if (codepoint &  16384) text[1] |=  4;
		if (codepoint &   8192) text[1] |=  2;
		if (codepoint &   4096) text[1] |=  1;

		text[2] = 128; // 10: 128,64
		if (codepoint & 2048) text[2] |= 32;
		if (codepoint & 1024) text[2] |= 16;
		if (codepoint &  512) text[2] |=  8;
		if (codepoint &  256) text[2] |=  4;
		if (codepoint &  128) text[2] |=  2;
		if (codepoint &   64) text[2] |=  1;

		text[3] = 128 | (codepoint & 63);

		return 4;	
	}

	return 0;
}

static int decodeHtmlRef(unsigned char * const full, const size_t lenFull, const size_t posRef, size_t * const lenOut) {
	size_t lenRef;
	unsigned int codepoint1 = 0;
	unsigned int codepoint2 = 0;

	const unsigned char * const src = full + posRef;
	const size_t lenSrc = lenFull - posRef;

	if (src[1] == '#') { // Numeric reference
		if (src[2] == 'x' || src[2] == 'X') { // Hex
			const unsigned char * const end = memchr(src + 3, ';', lenSrc - 3);
			if (end == NULL) return 0;
			lenRef = end - src;

			for (const unsigned char *c = src + 3; c < end; c++) {
				if (!isxdigit(*c)) return 0;
			}

			if (lenRef < 1) return 0; // Invalid

			codepoint1 = strtoul((char*)src + 3, NULL, 16);
		} else { // Decimal
			const unsigned char * const end = memchr(src + 2, ';', lenSrc - 3);
			if (end == NULL) return 0;
			lenRef = end - src;

			for (const unsigned char *c = src + 2; c < end; c++) {
				if (!isdigit(*c)) return 0;
			}

			if (lenRef < 1) return 0; // Invalid

			codepoint1 = strtoul((char*)src + 2, NULL, 10);
		}

		if (codepoint1 == 0x00A0 || (codepoint1 >= 0x2000 && codepoint1 <= 0x200A)) codepoint1 = ' '; // Various space characters

		lenRef++; // Include semicolon
	} else { // Named reference
		lenRef = strspn((char*)src + 1, "12345678ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmonpqrstuvwxyz"); // All alphanumerics except '0' and '9' occur in names
		if (lenRef < 2 || lenRef > 31) return 0; // Invalid
		if (src[lenRef + 1] == ';') lenRef++;

		unsigned char ref[lenRef + 1];
		memcpy(ref, src + 1, lenRef);
		ref[lenRef] = '\0';
		lenRef++; // Include ampersand

		codepoint1 = ref2codepoint(ref);
		if (codepoint1 == 0) ref2codepoint2(ref, &codepoint1, &codepoint2);
	}

	// We now have the codepoint(s)
	unsigned char new1[4];
	const size_t lenNew1 = utf8char(new1, codepoint1);

	unsigned char new2[4];
	const size_t lenNew2 = utf8char(new2, codepoint2);

	if (lenNew1 > 0) memcpy(full + *lenOut,           new1, lenNew1);
	if (lenNew2 > 0) memcpy(full + *lenOut + lenNew1, new2, lenNew2);
	*lenOut += lenNew1 + lenNew2;
	return lenRef;
}

int getHtmlCharacter(unsigned char * const src, const size_t lenSrc, const size_t posInput, size_t * const lenOut) {
	const size_t lenInput = lenSrc - posInput;

	if (lenInput >= 3 && src[posInput] == '&') {
		const int ret = decodeHtmlRef(src, lenSrc, posInput, lenOut);
		if (ret > 0) return ret;
	} else if (src[posInput] == ' ') {
		if (*lenOut < 1 // Space as first character
		|| src[*lenOut - 1] == ' ' // Repated spaces
		|| src[*lenOut - 1] == AEM_CET_CHAR_LBR // Space after linebreak
		|| src[*lenOut - 1] == AEM_CET_CHAR_SEP // Space as first character
		|| (src[*lenOut - 1] >= AEM_CET_THRESHOLD_LAYOUT && src[*lenOut - 1] < 32) // Space after layout element
		) return 1;
	} else if (src[posInput] < 32) {
		return 1;
	} else if (src[posInput] > 127) {
		const size_t lenSpace = charSpace(src + posInput, lenInput);
		if (lenSpace > 0) {
			src[*lenOut] = ' ';
			(*lenOut)++;
			return lenSpace;
		}
	}

	src[*lenOut] = src[posInput];
	(*lenOut)++;
	return 1;
}
