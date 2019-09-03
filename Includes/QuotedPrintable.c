#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Returns length of decoded string
int decodeQuotedPrintable(char * const * const data, size_t lenData) {
	char *c = memchr(*data, '=', lenData);
	size_t skip = 0;

	while (c != NULL) {
		skip = (c - *data) + 1;

		if (c[1] == '\n') {
			const size_t len = (*data + lenData) - c - 2;
			memmove(c, c + 2, len);
			lenData -= 2;
			skip -= 2;
		} else if (c[1] == '\r' && c[2] == '\n') {
			const size_t len = (*data + lenData) - c - 2;
			memmove(c, c + 3, len);
			lenData -= 3;
			skip -= 3;
		} else if (isxdigit(c[1]) && isxdigit(c[2])) {
			char hex[3];
			memcpy(hex, c + 1, 2);
			hex[2] = '\0';
			const unsigned char num = strtol(hex, NULL, 16);

			const size_t len = (*data + lenData) - c - 2;
			memmove(c + 1, c + 3, len);
			*c = (num == '=') ? '\0' : num;
			lenData -= 2;
			skip -= 2;
		}

		c = memchr(*data + skip, '=', lenData - skip);
	}

	while(1) {
		c = memchr(*data, '\0', lenData);
		if (c == NULL) break;
		*c = '=';
	}

	return lenData;
}
