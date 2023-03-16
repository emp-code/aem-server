#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "../Global.h"
#include "../Common/Trim.h"
#include "../Common/ValidUtf8.h"
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

static int decodeHtmlRef(unsigned char * const src, const size_t lenSrc, unsigned char * const decoded, size_t * const lenDecoded) {
	if (lenSrc < 4 || *src != '&') return 0;

	size_t lenRef;
	unsigned int codepoint1 = 0;
	unsigned int codepoint2 = 0;

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
	const size_t len1 = utf8char(decoded,        codepoint1);
	const size_t len2 = utf8char(decoded + len1, codepoint2);
	*lenDecoded = len1 + len2;

	return lenRef;
}

static int getHtmlChar(unsigned char * const src, const size_t lenSrc, unsigned char * const decoded, size_t * const lenDecoded) {
	int len = decodeHtmlRef(src, lenSrc, decoded, lenDecoded);
	if (len <= 0) {
		len = validUtf8(src, lenSrc, false);
		if (len > 0) {
			memcpy(decoded, src, len);
			*lenDecoded = len;
		}
	}

	return len;
}

// Ignores CET formatting chars
int prevChar(const unsigned char * const src, const int start, unsigned char * const result) {
	const int lenSrc = start;

	for (int i = start; i > 0; i--) {
		if (src[i] == AEM_CET_CHAR_LBR || src[i] >= AEM_CET_THRESHOLD_LAYOUT) {
			*result = src[i];
			return 1;
		} else {
			const int len = validUtf8(src + i, lenSrc - i, false);
			if (len > 0) {
				memcpy(result, src + i, len);
				return len;
			}
		}
	}

	return -1;
}

int addHtmlCharacter(unsigned char * const src, const size_t lenSrc, const size_t posInput, size_t * const lenOut) {
	size_t lenDec = 0;
	unsigned char dec[8];
	const int skip = getHtmlChar(src + posInput, lenSrc - posInput, dec, &lenDec);

	if (skip <= 0) {
		src[*lenOut] = '?';
		(*lenOut)++;
		return 1;
	}

	unsigned char prev[8];
	const int lenPrev = prevChar(src, *lenOut - 1, prev);

	if (charSpace(dec, lenDec) > 0) {
		if (lenPrev > 0 && *prev > 32 && *prev != AEM_CET_CHAR_SEP) {
			src[*lenOut] = ' ';
			(*lenOut)++;
		}

		return skip;
	}

	if (charInvisible(dec, lenDec) > 0) {
		if (lenPrev < 1
		|| charInvisible(prev, lenPrev) // Repeat
		|| src[*lenOut - 1] == AEM_CET_CHAR_LBR // Follows linebreak
		|| src[*lenOut - 1] == ' ' // Follows space
		|| src[*lenOut - 1] == AEM_CET_CHAR_SEP // As first character
		|| (src[*lenOut - 1] >= AEM_CET_THRESHOLD_LAYOUT && src[*lenOut - 1] < 32) // Follows layout element
		) return skip;
	}

	if (lenDec == 1 && (*dec < 32 || *dec == 127)) return 1;

	memcpy(src + *lenOut, dec, lenDec);
	*lenOut += lenDec;
	return skip;
}
