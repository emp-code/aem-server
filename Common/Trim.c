#define _GNU_SOURCE // for memmem

#include <stddef.h>
#include <string.h>

#include "Trim.h"

static void convertText(char * const text, size_t * const len, const char * const bad, const size_t lenBad, const char good) {
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

// Compress over two linebreaks spaces to two
void trimLinebreaks(char * const text, size_t * const len) {
	convertText(text, len, "\n\n\n", 3, '\n');
}
