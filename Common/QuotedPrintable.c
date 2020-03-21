#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

#include "QuotedPrintable.h"

__attribute__((warn_unused_result))
static unsigned char hexToChar(const char * const src) {
	char hex[3];
	memcpy(hex, src, 2);
	hex[2] = '\0';
	return strtoul(hex, NULL, 16);
}

void decodeQuotedPrintable(char * const data, size_t * const lenData) {
	while(1) {
		char * c = memmem(data, *lenData, "=\r\n", 3);
		if (c == NULL) break;

		const char * const copyFrom = c + 3;
		memmove(c, copyFrom, *lenData - (copyFrom - data));
		*lenData -= 3;
	}

	while(1) {
		char * c = memmem(data, *lenData, "=\n", 2);
		if (c == NULL) break;

		const char * const copyFrom = c + 2;
		memmove(c, copyFrom, *lenData - (copyFrom - data));
		*lenData -= 2;
	}

	while(1) {
		char * const enc = memchr(data, '=', *lenData - 1);
		if (enc == NULL) break;

		const ssize_t x = (data + *lenData) - (enc + 3);
		if (x < 0) break;

		*enc = hexToChar(enc + 1);
		if (*enc == '=') *enc = '\x01';

		memmove(enc + 1, enc + 3, x);
		*lenData -= 2;
	}

	while(1) {
		char * const equalsign = memchr(data, '\x01', *lenData);
		if (equalsign == NULL) break;
		*equalsign = '=';
	}
}
