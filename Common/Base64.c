#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>

#include "Base64.h"

static const unsigned char b64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

__attribute__((warn_unused_result))
unsigned char *b64Decode(const unsigned char * const src, const size_t srcLen, size_t * const outLen) {
	unsigned char dtable[256];
	memset(dtable, 0x80, 256);
	for (int i = 0; i < 64; i++) dtable[b64Table[i]] = (unsigned char)i;
	dtable['='] = 0;

	size_t count = 0;
	for (size_t i = 0; i < srcLen; i++) {
		if (dtable[src[i]] != 0x80) count++;
	}

	if (count == 0 || count % 4) return NULL;

	const size_t olen = count / 4 * 3;
	unsigned char *out = malloc(olen);
	if (out == NULL) return NULL;
	unsigned char *pos = out;

	int pad = 0;
	count = 0;
	for (size_t i = 0; i < srcLen; i++) {
		unsigned char block[4];
		const unsigned char tmp = dtable[src[i]];
		if (tmp == 0x80) continue;

		if (src[i] == '=') pad++;
		block[count] = tmp;
		count++;

		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;

			if (pad > 2) {free(out); return NULL;}
			if (pad > 0) {pos -= pad; break;}
		}
	}

	if (outLen != NULL) *outLen = pos - out;
	return out;
}
