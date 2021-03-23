#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "ref2codepoint.h"

#include "HtmlPlaceholders.h"

static size_t utf8char(unsigned char * const text, const unsigned int codepoint) {
	if (codepoint == 9 || codepoint == 10) { // Tab/Linefeed -> Space
		text[0] = ' ';
		return 1;
	}

	if (codepoint < 32 || codepoint == 127) return 0; // Control characters

	if (codepoint <= 0x007F) {
		switch (codepoint) {
			case '\n': text[0] = AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK; break;
			case '\'': text[0] = AEM_HTMLTOTEXT_PLACEHOLDER_SINGLEQUOTE; break;
			case '"':  text[0] = AEM_HTMLTOTEXT_PLACEHOLDER_DOUBLEQUOTE; break;
			case '<':  text[0] = AEM_HTMLTOTEXT_PLACEHOLDER_LT; break;
			case '>':  text[0] = AEM_HTMLTOTEXT_PLACEHOLDER_GT; break;
			default:   text[0] = codepoint; break;
		}

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

void decodeHtmlRefs(unsigned char * const text, size_t * const lenText) {
	unsigned char *c = memchr(text, '&', *lenText);

	while (c != NULL) {
		if ((text + *lenText) - c < 3) break;

		size_t lenRef;
		unsigned int codepoint1 = 0;
		unsigned int codepoint2 = 0;

		if (c[1] == '#') { // Numeric reference
			if (c[2] == 'x' || c[2] == 'X') { // Hex
				const unsigned char * const end = memchr(c + 3, ';', (text + *lenText) - c);
				if (end == NULL) break;

				lenRef = end - c;

				for (const unsigned char *d = c + 3; d != end; d++) {
					if (!isxdigit(*d)) {
						lenRef = 0;
						break;
					}
				}

				if (lenRef < 1) break; // Invalid

				codepoint1 = strtol((char*)c + 3, NULL, 16);
			} else { // Decimal
				const unsigned char * const end = memchr(c + 2, ';', (text + *lenText) - c);
				if (end == NULL) break;

				lenRef = end - c;

				for (const unsigned char *d = c + 2; d != end; d++) {
					if (!isdigit(*d)) {
						lenRef = 0;
						break;
					}
				}

				if (lenRef < 1) break; // Invalid

				codepoint1 = strtol((char*)c + 2, NULL, 10);
			}

			lenRef++; // Include semicolon
		} else { // Named reference
			lenRef = strspn((char*)c + 1, "12345678ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmonpqrstuvwxyz"); // All alphanumerics except '0' and '9' occur in names
			if (lenRef < 2) {c = memchr(c + 1 + lenRef, '&', (text + *lenText) - (c + 1 + lenRef)); continue;} // Invalid
			if (c[lenRef + 1] == ';') lenRef++;

			unsigned char ref[lenRef + 1];
			memcpy(ref, c + 1, lenRef);
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

		if (lenNew1 + lenNew2 > 0) {
			const size_t offset = (c - text) + lenNew1 + lenNew2;

			if (lenNew1 + lenNew2 <= lenRef) {
				memcpy(c, new1, lenNew1);
				if (lenNew2 > 0) memcpy(c + lenNew1, new2, lenNew2);

				if (lenNew1 + lenNew2 < lenRef) {
					memmove(c + lenNew1 + lenNew2, c + lenRef, (text + *lenText) - (c + lenRef));
					*lenText -= lenRef - (lenNew1 + lenNew2);
					(text)[*lenText] = '\0';
				}

				c = memchr(text + offset, '&', *lenText - offset);
			} else {
				// Not supported, UTF-8 is larger than encoded form. Only &nGt; and &nLt (much greater/lesser than with vertical line).
				c = memchr(c + 1 + lenRef, '&', (text + *lenText) - (c + 1 + lenRef));
			}
		} else c = memchr(c + 1 + lenRef, '&', (text + *lenText) - (c + 1 + lenRef));
	}
}
