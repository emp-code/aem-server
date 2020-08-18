#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "Trim.h"

void removeControlChars(unsigned char * const text, size_t * const len) {
	unsigned char * const new = malloc(*len);
	size_t lenNew = 0;

	for (size_t i = 0; i < *len; i++) {
		if ((text[i] > 31 && text[i] != 127) || text[i] == '\n') { // 127=DEL
			new[lenNew] = text[i];
			lenNew++;
		} else if (text[i] == '\t') {
			new[lenNew] = ' ';
			lenNew++;
		} else if (text[i] == '\f' || (i < (*len - 1) && text[i] == '\r' &&  text[i + 1] != '\n')) {
			new[lenNew] = '\n';
			lenNew++;
		}
	}

	memcpy(text, new, lenNew);
	free(new);
	*len = lenNew;
}

void convertText(char * const text, size_t * const lenText, const char * const bad, const size_t lenBad, const char good) {
	const size_t diff = lenBad - 1;

	while(1) {
		char * const c = memmem(text, *lenText, bad, lenBad);
		if (c == NULL) break;

		memmove(c + 1, c + lenBad, (text + *lenText) - (c + lenBad));
		*c = good;
		*lenText -= diff;
	}
}

void convertLineDots(char * const text, size_t * const len) {
	char *c = memmem(text, *len, "\n..", 3);

	while (c != NULL) {
		const size_t offset = (c + 2) - text;

		memmove(c + 1, c + 2, *len - offset);
		(*len)--;

		c = memmem(text + offset, *len - offset, "\n..", 3);
	}
}

// Convert non-breaking space to normal space (UTF-8)
void convertNbsp(char * const text, size_t * const len) {
	convertText(text, len, "\xc2\xa0", 2, ' ');
}

// Compress multiple spaces to one
void trimSpace(char * const text, size_t * const len) {
	convertText(text, len, "  ", 2, ' ');
}

// Remove space before linebreak
void removeSpaceEnd(char * const text, size_t * const len) {
	convertText(text, len, " \n", 2, '\n');
}

// Remove space after linebreak
void removeSpaceBegin(char * const text, size_t * const len) {
	convertText(text, len, "\n ", 2, '\n');
}

// Compress over two linebreaks to two
void trimLinebreaks(char * const text, size_t * const len) {
	convertText(text, len, "\n\n\n", 3, '\n');
}

void trimBegin(char * const text, size_t * const len) {
	size_t rem = 0;
	for (size_t i = 0; i < *len; i++) {
		if (!isspace(text[i])) break;
		rem++;
	}

	if (rem < 1) return;
	memmove(text, text + rem, *len - rem);
	*len -= rem;
}

void trimEnd(const char * const text, size_t * const len) {
	for (int i = *len - 1; i >= 0; i--) {
		if (!isspace(text[i])) break;
		(*len)--;
	}
}
