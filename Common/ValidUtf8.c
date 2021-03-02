#include "ValidUtf8.h"

bool isValidUtf8(const unsigned char * const src, const size_t len) {
	for (size_t i = 0; i < len; i++) {
		// 1-byte ASCII
		if ((src[i] >= 32 && src[i] < 127) || src[i] == '\t' || src[i] == '\n') continue; // ASCII printable, space/tab/newline
		if (src[i] < 32 || src[i] == 127) return false; // ASCII control characters

		// Multibyte Unicode
		if ((src[i] & 248) == 240) { // 4-byte
			if (i + 3 > len
			|| (src[i] & 7) != 0 // Forbid code points above 0x3FFFF (unassigned, Private Use)
			|| (src[i + 1] & 192) != 128
			|| (src[i + 2] & 192) != 128
			|| (src[i + 3] & 192) != 128
			) return false;

			i += 3;
		} else if ((src[i] & 240) == 224) { // 3-byte
			if (i + 2 > len
			|| (src[i + 1] & 192) != 128
			|| (src[i + 2] & 192) != 128
			) return false;

			i += 2;
		} else if ((src[i] & 224) == 192) { // 2-byte
			if (i + 1 > len
			|| (src[i + 1] & 192) != 128
			) return false;

			i++;
		} else return false;
	}

	return true;
}
