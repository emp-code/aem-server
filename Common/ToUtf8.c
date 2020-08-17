#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <unicode/ucnv.h>

#include "ToUtf8.h"

bool isUtf8(const char * const charset, const size_t lenCs) {
	return (charset != NULL && (
	   (lenCs >= 4 && strncasecmp(charset, "utf8", 4) == 0)
	|| (lenCs >= 5 && strncasecmp(charset, "utf", 3) == 0 && charset[4] == '8')
	|| (lenCs >= 5 && strncasecmp(charset, "ascii", 5) == 0)
	|| (lenCs >= 8 && strncasecmp(charset, "us-ascii", 8) == 0)
	));
}

char *toUtf8(const char * const input, const size_t lenInput, size_t * const lenOut, const char * const charset) {
	if (input == NULL || lenInput < 1 || lenOut == NULL || charset == NULL) return NULL;

	if (isUtf8(charset, strlen(charset))) {
		char * const new = malloc(lenInput);
		memcpy(new, input, lenInput);
		*lenOut = lenInput;
		return new;
	}

	const size_t maxLen = lenInput * 2;

	char * const buf = malloc(maxLen + 1);
	if (buf == NULL) return NULL;

	UErrorCode status = U_ZERO_ERROR;
	const int newLen = ucnv_convert("utf-8", charset, buf, maxLen, input, lenInput, &status);

	if (U_FAILURE(status) || newLen < 1) {
		free(buf);
		return NULL;
	}

	*lenOut = newLen;
	return buf;
}
