#include <stdint.h>
#include <stddef.h>

static uint8_t b64_decodeChar(const char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+' || c == '-') return 62;
	if (c == '/' || c == '_') return 63;
	return UINT8_MAX;
}

void aem_base642bin(unsigned char * const src, size_t * const len) {
	if (src == NULL || len == NULL || *len < 1) return;

	size_t pos = 0;
	size_t newLen = 0;

	for(;;) {
		uint8_t x[4] = {UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX};

		for (int i = 0; i < 4;) {
			if (pos + 1 == *len) break;
			x[i] = b64_decodeChar(src[pos]);
			pos++;
			if (x[i] < 64) i++;
		}

		if (x[0] > 63 || x[1] > 63) break;
		src[newLen] = (x[0] << 2) | ((x[1] & 48) >> 4);
		newLen++;

		if (x[2] > 63) break;
		src[newLen] = (x[1] << 4) | (x[2] >> 2);
		newLen++;

		if (x[3] > 63) break;
		src[newLen] = ((x[2] & 3) << 6) | x[3];
		newLen++;
	}

	*len = newLen;
}
