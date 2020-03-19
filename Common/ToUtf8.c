#include <stdlib.h>
#include <string.h>
#include <unicode/ucnv.h>

#include "ToUtf8.h"

char *toUtf8(const char * const input, const size_t lenInput, int * const lenOut, const char * const charset) {
	if (input == NULL || lenInput < 1 || lenOut == NULL || charset == NULL) return NULL;
	if (strncasecmp(charset, "utf8", 4) == 0 || (strlen(charset) > 4 && strncasecmp(charset, "utf", 3) == 0 && charset[5] == '8')) return strndup(input, lenInput);

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
