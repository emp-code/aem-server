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
			const unsigned char h = data[i];

			if (h >= 32 && h != 127) { // 127 = del
				new[lenNew] = h;
				lenNew++;
			} else if (h == '\t') {
				new[lenNew] = ' ';
				lenNew++;
			} else if (isspace(h)) {
				new[lenNew] = '\n';
				lenNew++;
			}

			continue;
		}

		i++; // Skip '='
		if (i >= *lenData) break;
		if (data[i] == '\n') continue;
		if (i >= *lenData - 1) break;

		const unsigned long h = hexToChar(data + i);

		if (h >= 32 && h != 127) { // 127 = del
			new[lenNew] = (char)h;
			lenNew++;
		} else if (h == '\t') {
			new[lenNew] = ' ';
			lenNew++;
		} else if (isspace(h)) {
			new[lenNew] = '\n';
			lenNew++;
		}

		i++;
	}

	memcpy(data, new, lenNew);
	free(new);
	*lenData = lenNew;
	data[*lenData] = '\0';
}
