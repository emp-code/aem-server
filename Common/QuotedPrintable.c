#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "QuotedPrintable.h"

__attribute__((warn_unused_result))
static unsigned long hexToChar(const char * const src) {
	const char hex[3] = {src[0], src[1], '\0'};
	return strtoul(hex, NULL, 16);
}

void decodeQuotedPrintable(char * const data, size_t * const lenData) {
	char * const new = malloc(*lenData);
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
		if (data[i] == '\r' && data[i + 1] == '\n') {i++; continue;}
		// TODO if not hex

		const unsigned char h = hexToChar(data + i);
		memcpy(new + lenNew, &h, 1);
		lenNew++;

		i++;
	}

	memcpy(data, new, lenNew);
	free(new);
	*lenData = lenNew;
	data[*lenData] = '\0';
}
