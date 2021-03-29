#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <unicode/ucnv.h>

#include "ToUtf8.h"

bool isUtf8(const char * const charset) {
	return (charset != NULL && (
	(strncasecmp(charset, "utf", 3) == 0 && charset[4] == '8')
	|| strcasecmp(charset, "utf8") == 0
	|| strcasecmp(charset, "ascii") == 0
	|| strcasecmp(charset, "us-ascii") == 0
	));
}

unsigned char *toUtf8(const char * const input, const size_t lenInput, size_t * const lenOut, const char * const charset) {
	if (input == NULL || lenInput < 1 || lenOut == NULL || charset == NULL) return NULL;

	if (isUtf8(charset)) {
		unsigned char * const new = malloc(lenInput + 1);
		if (new == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}
		memcpy(new, input, lenInput);
		new[lenInput] = '\0';
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
	return (unsigned char*)buf;
}
