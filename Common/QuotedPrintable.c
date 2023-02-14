#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "QuotedPrintable.h"

__attribute__((warn_unused_result))
static unsigned long hexToChar(const unsigned char * const src) {
	const char hex[3] = {src[0], src[1], '\0'};
	return strtoul(hex, NULL, 16);
}

void decodeQuotedPrintable(unsigned char * const data, size_t * const lenData) {
	unsigned char * const new = malloc(*lenData);
	if (new == NULL) return;
	size_t lenNew = 0;

	for (size_t i = 0; i < *lenData; i++) {
		if (data[i] != '=') {
			new[lenNew] = data[i];
			lenNew++;
			continue;
		}

		i++; // Skip '='
		if (i >= *lenData) break;
		if (i >= *lenData - 1) break;
		if (data[i] == '\n') continue;

		if (isxdigit(data[i]) && isxdigit(data[i + 1])) {
			unsigned char h = hexToChar(data + i);
			if (h == '\t') h = ' ';

			if (h == '\n' || (h >= 32 && h != 127)) {
				memcpy(new + lenNew, &h, 1);
				lenNew++;
			}
		} else {
			memcpy(new + lenNew, data + i - 1, 3); // Include '='
			lenNew += 3;
		}

		i++;
	}

	memcpy(data, new, lenNew);
	free(new);
	*lenData = lenNew;
	data[*lenData] = '\0';
}
