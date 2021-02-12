#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "Trim.h"

void removeControlChars(unsigned char * const text, size_t * const len) {
	if (text == NULL || len == NULL) return;

	unsigned char * const new = malloc(*len);
	if (new == NULL) return;

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

void convertText(unsigned char * const text, size_t * const lenText, const char * const bad, const size_t lenBad, const char good) {
	if (text == NULL || lenText == NULL || bad == NULL) return;

	const size_t diff = lenBad - 1;

	while(1) {
		unsigned char * const c = memmem(text, *lenText, bad, lenBad);
		if (c == NULL) break;

		memmove(c + 1, c + lenBad, (text + *lenText) - (c + lenBad));
		*c = good;
		*lenText -= diff;
	}
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

// Convert non-breaking space to normal space (UTF-8)
void convertNbsp(unsigned char * const text, size_t * const len) {
	convertText(text, len, (char[]){0xc2, 0xa0}, 2, ' ');
}

// Compress multiple spaces to one
void trimSpace(unsigned char * const text, size_t * const len) {
	convertText(text, len, "  ", 2, ' ');
}

// Remove space before linebreak
void removeSpaceEnd(unsigned char * const text, size_t * const len) {
	convertText(text, len, " \n", 2, '\n');
}

// Remove space after linebreak
void removeSpaceBegin(unsigned char * const text, size_t * const len) {
	convertText(text, len, "\n ", 2, '\n');
}

// Compress over two linebreaks to two
void trimLinebreaks(unsigned char * const text, size_t * const len) {
	convertText(text, len, "\n\n\n", 3, '\n');
}

void trimBegin(unsigned char * const text, size_t * const len) {
	size_t rem = 0;
	for (size_t i = 0; i < *len; i++) {
		if (!isspace(text[i])) break;
		rem++;
	}

	if (rem < 1) return;
	memmove(text, text + rem, *len - rem);
	*len -= rem;
}

void trimEnd(const unsigned char * const text, size_t * const len) {
	for (int i = *len - 1; i >= 0; i--) {
		if (!isspace(text[i])) break;
		(*len)--;
	}
}
