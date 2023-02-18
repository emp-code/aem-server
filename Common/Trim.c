#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "Trim.h"

void removeControlChars(unsigned char * const c, size_t * const len) {
	size_t newLen = 0;

	for (size_t i = 0; i < *len; i++) {
		if (c[i] == '\n' || (c[i] >= 32 && c[i] != 127)) {
			c[newLen] = c[i];
			newLen++;
		} else if (c[i] == '\t') {
			c[newLen] = ' ';
			newLen++;
		}
	}

	*len = newLen;
}

static size_t charInvisible(const unsigned char * const c, const size_t len) {
	if (len > 1 && c[0] == 0xCD && c[1] == 0x8F) return 2; // CGJ

	if (len > 2 && (
	   (c[0] == 0xE2 && c[1] == 0x80 && (c[2] >= 0x8B && c[2] <= 0x8D)) // ZWSP/ZWNJ/ZWJ
	|| (c[0] == 0xE2 && c[1] == 0x81 && c[2] == 0xA0) // WJ
	|| (c[0] == 0xEF && c[1] == 0xBB && c[2] == 0xBF) // ZWNBSP
	)) return 3;

	return 0;
}

static size_t charSpace(const unsigned char * const c, const size_t len) {
	if (len > 0 && c[0] == ' ') return 1;

	if (len > 1 && c[0] == 0xC2 && c[1] == 0xA0) return 2; // NBSP

	if (len > 2 && (
	   (c[0] == 0xE1 && c[1] == 0x9A && c[2] == 0x80) // OSM
	|| (c[0] == 0xE2 && c[1] == 0x80 && (c[2] >= 0x80 && c[2] <= 0x8A)) // Various size spaces
	|| (c[0] == 0xE2 && c[1] == 0x80 && c[2] >= 0xAF) // NARROW NO-BREAK SPACE
	|| (c[0] == 0xE2 && c[1] == 0x81 && c[2] >= 0x9F) // MEDIUM MATHEMATICAL SPACE
	|| (c[0] == 0xE3 && c[1] == 0x80 && c[2] >= 0x80) // IDEOGRAPHIC SPACE
	)) return 3;

	return 0;
}

static size_t charNewline(const unsigned char * const c, const size_t len) {
	if (len > 0 && c[0] == '\n') return 1;
	if (len > 1 && c[0] == 0xC2 && c[1] == 0x85) return 2; // NL
	if (len > 2 && c[0] == 0xE2 && c[1] == 0x80 && (c[2] == 0xA8 || c[2] == 0xA9)) return 3; // Line/Paragraph Separator

	return 0;
}

// Get the prev/next character, ignoring CCs
size_t prevCharAt(unsigned char * const src, const ssize_t start) {
	if (start < 1) return 0;

	const unsigned char *c = src + start;
	while (c > src && ((*c < 32 && *c != '\n') || *c == 127)) {
		c--;
	}

	return c - src;
}

size_t nextCharAt(unsigned char * const src, const size_t start, const size_t len) {
	const unsigned char *c = src + start;
	while (c < src + len && ((*c < 32 && *c != '\n') || *c == 127)) {
		c++;
	}

	return c - src;
}

void cleanText(unsigned char * const c, size_t * const len) {
	size_t newLen = 0;
	size_t noCheck = 0;

	for (size_t i = 0; i < *len; i++) {
		if (noCheck == 0) {
			size_t x = charInvisible(c + i, *len - i);
			if (x > 0) {
				const size_t o1 = nextCharAt(c, i + x, *len);
				if (charSpace(c + o1, *len - o1) > 0 || charNewline(c + o1, *len - o1) > 0) {i += x - 1; continue;} // A space/newline follows this invisible character - delete this invisble character

				const size_t y = charInvisible(c + i + x, *len - i - x);
				if (y > 0) {i += x + y - 1; continue;} // Another invisible characters follows this one - delete both

				noCheck = x - 1; // Allow through
			}

			x = charSpace(c + i, *len - i);
			if (x > 0) {
				const size_t o1 = nextCharAt(c, i + x, *len);
				const size_t o2 = prevCharAt(c, newLen - 1);

				if (newLen < 1 // First character shouldn't be space
				|| (c[o2] == ' ') // Preceded by a space
				|| (c[o2] == '\n') // Preceded by a newline
				|| charNewline(c + o1, *len - o1) > 0 // Followed by a newline
				) {i += x - 1; continue;} // Delete this space

				// Add a normal space
				c[newLen] = ' ';
				newLen++;
				i += x - 1;
				continue;
			}

			x = charNewline(c + i, *len - i);
			if (x > 0) {
				const size_t o1 = prevCharAt(c, newLen - 1);
				const size_t o2 = prevCharAt(c, o1 - 1);

				if (newLen < 2 || (c[o1] == '\n' && c[o2] == '\n')) { // This newline is the first character, or is preceded by 2 newlines - delete this newline
					i += x - 1;
					continue;
				}

				// Add a normal newline
				c[newLen] = '\n';
				newLen++;
				i += x - 1;
				continue;
			}
		} else {
			noCheck--;
		}

		c[newLen] = c[i];
		newLen++;
	}

	// Remove whitespace at the end
	for (int i = newLen - 1; i >= 0; i--) {
		if (c[i] != ' ' && c[i] != '\n') break;
		newLen--;
	}

	*len = newLen;
}
