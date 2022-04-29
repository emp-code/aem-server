#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "Trim.h"

// Converts HT/NBSP/etc to SP; Converts VT/FF to LF; Removes other control characters
void removeControlChars(unsigned char * const text, size_t * const len) {
	if (text == NULL || len == NULL) return;

	unsigned char * const new = malloc(*len);
	if (new == NULL) return;

	size_t lenNew = 0;

	for (size_t i = 0; i < *len; i++) {
		if ((i + 2 < *len) && text[i] == 0xE2 && text[i + 1] == 0x80 && (text[i + 2] >= 0x80 && text[i + 2] <= 0x8A)) { // Whitespace of various sizes
			new[lenNew] = ' ';
			lenNew++;
			i += 2;
		} else if ((i + 1 < *len) && text[i] == 0xC2 && text[i + 1] == 0xA0) { // NBSP
			new[lenNew] = ' ';
			lenNew++;
			i++;
		} else if (text[i] >= 32 && text[i] != 127) { // 127=DEL
			new[lenNew] = text[i];
			lenNew++;
		} else if (text[i] == '\n' || text[i] == '\v' || text[i] == '\f') {
			new[lenNew] = '\n';
			lenNew++;
		} else if (text[i] == '\t') {
			new[lenNew] = ' ';
			lenNew++;
		}
	}

	memcpy(text, new, lenNew);
	free(new);
	*len = lenNew;
}

// Compresses multiple LF/SP to one; Removes SP followed by/following LF; Removes control characters
void cleanText(unsigned char * const text, size_t * const len, const bool removeControl) {
	if (text == NULL || len == NULL) return;

	unsigned char * const new = malloc(*len);
	if (new == NULL) return;

	size_t lenNew = 0;

	for (size_t i = 0; i < *len; i++) {
		if ((i + 2 < *len) && text[i] == 0xEF && text[i + 1] == 0xBB && text[i + 2] == 0xBF) { // BOM - useless in UTF-8
			i += 2;
			continue;
		} else if ((i + 2 < *len) && text[i] == 0xE2 && text[i + 1] == 0x80 && text[i + 2] == 0x8C) { // ZWNJ
			if (lenNew > 0 && new[lenNew - 1] == '\n') {i += 2; continue;} // Follows LF - skip
			if ((i + 3 < *len) && (text[i + 3] == ' ' || text[i + 3] == '\n')) {i += 2; continue;} // Followed by SP/LF - skip
			new[lenNew] = text[i];
			new[lenNew + 1] = text[i + 1];
			new[lenNew + 2] = text[i + 2];
			lenNew += 3;
			i += 2;
			continue;
		} else if ((i + 1 < *len) && text[i] == 0xC2 && text[i + 1] == 0xA0) { // NBSP
			if (lenNew > 0 && new[lenNew - 1] == '\n') {i++; continue;} // follows LF - skip
			if (i + 4 < *len && text[i + 2] == 0xE2 && text[i + 3] == 0x80 && text[i + 4] == 0x8C) {i += 4; continue;} // Followed by ZWNJ
			if ((i + 2 < *len) && (text[i + 2] == ' ' || text[i + 2] == '\n')) {i++; continue;} // Followed by SP/LF - skip
			new[lenNew] = text[i];
			new[lenNew + 1] = text[i + 1];
			lenNew += 2;
			i++;
			continue;
		} else if (text[i] == ' ') {
			if (lenNew > 0 && new[lenNew - 1] == '\n') continue; // follows LF - skip
			if ((i + 1 < *len) && (text[i + 1] == ' ' || text[i + 1] == '\n')) continue; // Followed by SP/LF - skip
		} else if (text[i] == '\n') {
			if (lenNew > 1 && new[lenNew - 1] == '\n' && new[lenNew - 2] == '\n') continue; // Follows 2 LF - skip
		} else if (removeControl && (text[i] < 32 || text[i] == 127)) { // 127=DEL
			continue;
		}

		new[lenNew] = text[i];
		lenNew++;
	}

	size_t skip = 0;
	while (skip < lenNew && (new[skip] == '\n' || new[skip] == ' ')) skip++;

	memcpy(text, new + skip, lenNew - skip);
	free(new);
	*len = lenNew - skip;

	while (*len > 0 && (text[*len - 1] == '\n' || text[*len - 1] == ' ')) (*len)--;
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
