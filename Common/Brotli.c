#include <stdlib.h>
#include <syslog.h>

#include <brotli/encode.h>

__attribute__((warn_unused_result))
int brotliCompress(unsigned char ** const holder, size_t * const lenData) {
	size_t lenOut = *lenData;
	if (lenOut < 100) lenOut += 100; // compressed version can be larger with very small files
	unsigned char * const output = malloc(lenOut);
	if (output == NULL) {syslog(LOG_ERR, "Failed allocation"); return -1;}

	if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_DEFAULT_MODE, *lenData, *holder, &lenOut, output) == BROTLI_FALSE) {
		free(output);
		return -1;
	}

	free(*holder);
	*holder = realloc(output, lenOut);
	if (*holder == NULL) {free(output); return -1;}
	*lenData = lenOut;

	return 0;
}
