#define _GNU_SOURCE // for memmem

#include <stdlib.h>
#include <string.h>

// Convert non-breaking space to normal space (UTF-8)
void convertNbsp(char * const text, size_t * const len) {
	while(1) {
		char *c = memmem(text, *len, "\xc2\xa0", 2);
		if (c == NULL) break;

		*len -= 1;
		memmove(c, c + 1, (text + *len) - c);
		*c = ' ';
	}
}

// Compress multiple spaces to one
void trimSpace(char * const text, size_t * const len) {
	char *c = memchr(text, ' ', *len);

	while (c != NULL) {
		while (c[1] == ' ') {
			(*len)--;
			memmove(c, c + 1, (text + *len) - c);

			if (c == (text + *len)) return;
		}

		c = memchr(c + 1, ' ', (text + *len) - c);
	}
}

// Remove space before linebreak
void removeSpaceEnd(char * const text, size_t * const len) {
	char *c = memmem(text, *len, " \n", 2);
	while (c != NULL) {
		*len -= 1;
		memmove(c, c + 1, (text + *len) - c);

		c = memmem(c + 1, (text + *len) - c, " \n", 2);
	}
}

// Remove space after linebreak
void removeSpaceBegin(char * const text, size_t * const len) {
	char *c = memmem(text, *len, "\n ", 2);
	while (c != NULL) {
		*len -= 1;
		c++;
		memmove(c, c + 1, (text + *len) - c);

		c = memmem(c, (text + *len) - c, "\n ", 2);
	}
}

// Compress over two linebreaks spaces to two
void trimLinebreaks(char * const text, size_t * const len) {
	char *c = memmem(text, *len, "\n\n\n", 3);

	while (c != NULL) {
		c++;

		while (c[1] == '\n') {
			(*len)--;
			memmove(c, c + 1, (text + *len) - c);

			if (c == (text + *len)) return;
		}

		c = memmem(text, *len, "\n\n\n", 3);
	}
}
