#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "Trim.h"

/* Converts HT/NBSP to SP
 * Converts VT/FF to LF
 * Removes other control-chars
 * Compresses multiple LF/SP to one
 * Removes SP followed by/following LF
 */
void cleanText(unsigned char * const text, size_t * const len) {
	if (text == NULL || len == NULL) return;

	unsigned char * const new = malloc(*len);
	if (new == NULL) return;

	size_t lenNew = 0;

	for (size_t i = 0; i < *len; i++) {
		if ((i + 1 < *len) && text[i] == 0xc2 && text[i + 1] == 0xa0) { // NBSP
			new[lenNew] = ' ';
			lenNew++;
			i++;
		} else if (text[i] > 32 && text[i] != 127) { // 127=DEL
			new[lenNew] = text[i];
			lenNew++;
		} else if (text[i] == '\t' || text[i] == ' ') {
			if (lenNew > 0 && (new[lenNew - 1] == ' ' || new[lenNew - 1] == '\n')) continue; // follows SP/LF - skip
			if ((i + 1 < *len) && text[i + 1] == '\n') continue; // followed by LF - skip

			new[lenNew] = ' ';
			lenNew++;
		} else if (text[i] == '\n' || text[i] == '\v' || text[i] == '\f') {
			if (lenNew > 1 && new[lenNew - 1] == '\n' && new[lenNew - 2] == '\n') continue; // follows 2 LF - skip

			new[lenNew] = '\n';
			lenNew++;
		}
	}

	size_t skip = 0;
	while (skip < *len && isspace(new[skip])) skip++;

	memcpy(text, new + skip, lenNew - skip);
	free(new);
	*len = lenNew - skip;

	while (*len > 0 && isspace(text[*len - 1])) (*len)--;
}

void convertLineDots(unsigned char * const text, size_t * const len) {
	unsigned char *c = memmem(text, *len, "\r\n..", 4);

	while (c != NULL) {
		c += 2;
		const size_t offset = (c + 1) - text;

		memmove(c, c + 1, *len - offset);
		(*len)--;

		c = memmem(text + offset, *len - offset, "\r\n..", 4);
	}
}
