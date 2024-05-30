#include <stdlib.h>
#include <string.h>

#include "ValidUtf8.h"

// Checks an individual character, returns its size in bytes, negative if invalid
int validUtf8(const unsigned char * const src, const size_t len, const bool allowControl) {
	// 1-byte ASCII
	if ((src[0] >= 32 && src[0] < 127) || src[0] == '\t' || src[0] == '\n') return 1; // ASCII printable, space/tab/newline
	if (src[0] < 32 || src[0] == 127) return allowControl? 1 : -1; // ASCII control characters

	// Multibyte Unicode
	if ((src[0] & 248) == 240) { // 4-byte
		return (len < 4
		|| (src[0] & 7) != 0 // Forbid code points above 0x3FFFF (unassigned, Private Use)
		|| (src[1] & 192) != 128
		|| (src[2] & 192) != 128
		|| (src[3] & 192) != 128
		) ? -4 : 4;
	} else if ((src[0] & 240) == 224) { // 3-byte
		return (len < 3
		|| (src[1] & 192) != 128
		|| (src[2] & 192) != 128
		) ? -3 : 3;
	} else if ((src[0] & 224) == 192) { // 2-byte
		return (len < 2
		|| (src[1] & 192) != 128
		) ? -2 : 2;
	}

	return -1; // Invalid
}

bool isValidUtf8(const unsigned char * const src, const size_t len) {
	for (size_t i = 0; i < len;) {
		const int s = validUtf8(src + i, len - i, false);
		if (s < 0) return false;
		i += s;
	}

	return true;
}

void filterUtf8(unsigned char * const src, const size_t len, const bool allowControl) {
	for (size_t i = 0; i < len;) {
		const int s = validUtf8(src + i, len - i, allowControl);

		if (s < 0) {
			if (i + abs(s) >= len) {
				memset(src + i, '?', len - i);
				return;
			}

			memset(src + i, '?', abs(s));
		}

		i += abs(s);
	}
}
