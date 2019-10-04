#include <stdlib.h>

#include <brotli/encode.h>

int brotliCompress(char ** const holder, size_t * const lenData) {
	size_t lenOut = *lenData;
	if (lenOut < 100) lenOut += 100; // compressed version can be larger with very small files
	uint8_t * const output = malloc(lenOut);

	if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_DEFAULT_MODE, *lenData, (uint8_t*)(*holder), &lenOut, output) == BROTLI_FALSE) {
		free(output);
		return -1;
	}

	free(*holder);
	*holder = realloc(output, lenOut);
	if (*holder == NULL) return -1;
	*lenData = lenOut;

	return 0;
}
