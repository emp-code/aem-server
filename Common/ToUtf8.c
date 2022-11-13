#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <sodium.h>
#include <unicode/ucnv.h>

#include "../Common/memeq.h"

#include "ToUtf8.h"

bool isUtf8(const char * const charset) {
	return (charset != NULL && (
	   memeq_anycase(charset, "utf8", 4)
	|| memeq_anycase(charset, "utf-8", 5)
	|| memeq_anycase(charset, "utf_8", 5)
	|| memeq_anycase(charset, "ascii", 5)
	|| memeq_anycase(charset, "us-ascii", 8)
	|| memeq_anycase(charset, "us_ascii", 8)
	));
}

char *toUtf8(const char * const input, const size_t lenInput, size_t * const lenOut, const char * const charset) {
	if (input == NULL || lenInput < 1 || lenOut == NULL || charset == NULL) return NULL;

	if (isUtf8(charset)) {
		char * const new = sodium_malloc(lenInput + 1);
		if (new == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}
		memcpy(new, input, lenInput);
		new[lenInput] = '\0';
		*lenOut = lenInput;
		return new;
	}

	const size_t maxLen = lenInput * 2;

	char * const buf = sodium_malloc(maxLen + 1);
	if (buf == NULL) return NULL;

	UErrorCode status = U_ZERO_ERROR;
	const int newLen = ucnv_convert("utf-8", charset, buf, maxLen, input, lenInput, &status);

	if (U_FAILURE(status) || newLen < 1) {
		sodium_free(buf);
		return NULL;
	}

	*lenOut = newLen;
	return buf;
}
