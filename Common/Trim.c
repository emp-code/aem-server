#define _GNU_SOURCE // for memmem

#include <stdlib.h>
#include <string.h>

// Convert non-breaking space to normal space (UTF-8)
void convertNbsp(char * const text, size_t * const len) {
	while(1) {
		char *c = memmem(text, *len, "\xc2\xa0", 2);
		if (c == NULL) break;

		memmove(c, c + 1, (text + *len) - (c + 1));
		*len -= 1;
		*c = ' ';
	}
}

// Compress multiple spaces to one
void trimSpace(char * const text, size_t * const len) {
	while(1) {
		char *c = memmem(text, *len, "  ", 2);
		if (c == NULL) break;

		memmove(c, c + 1, (text + *len) - (c + 1));
		*len -= 1;
	}
}

// Remove space before linebreak
void removeSpaceEnd(char * const text, size_t * const len) {
	while(1) {
		char *c = memmem(text, *len, " \n", 2);
		if (c == NULL) break;

		memmove(c, c + 1, (text + *len) - (c + 1));
		*len -= 1;
	}
}

// Remove space after linebreak
void removeSpaceBegin(char * const text, size_t * const len) {
	while(1) {
		char *c = memmem(text, *len, "\n ", 2);
		if (c == NULL) break;

		memmove(c, c + 1, (text + *len) - (c + 1));
		*len -= 1;
		*c = '\n';
	}
}

// Compress over two linebreaks spaces to two
void trimLinebreaks(char * const text, size_t * const len) {
	while (1) {
		char *c = memmem(text, *len, "\n\n\n", 3);
		if (c == NULL) break;

		memmove(c, c + 1, (text + *len) - (c + 1));
		*len -= 1;
	}
}
