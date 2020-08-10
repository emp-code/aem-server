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

static void convertText(char * const text, size_t * const len, const char * const bad, const size_t lenBad, const char good) {
	if (text == NULL || len == NULL || *len < 1 || bad == NULL || lenBad < 1) return;

	while(1) {
		char * const c = memmem(text, *len, bad, lenBad);
		if (c == NULL) break;

		memmove(c, c + 1, (text + *len) - (c + 1));
		(*len)--;
		*c = good;
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

void trimEnd(const char * const text, size_t * const len) {
	for (int i = *len - 1; i >= 0; i--) {
		if (text[i] != ' ' && text[i] != '\n') break;

		(*len)--;
	}
}
