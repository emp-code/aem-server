#include <stdlib.h>
#include <string.h>

#include "b64dec.h"

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned char *b64Decode(const char *in, size_t inLen, size_t *outLen) {
	unsigned char dtable[256];
	memset(dtable, 0x80, 256);

	for (int i = 0; i < sizeof(base64_table) - 1; i++) dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	size_t count = 0;
	for (int i = 0; i < inLen; i++) {if (dtable[in[i]] != 0x80) count++;}
	if (count == 0 || count % 4) return NULL;

	unsigned char *out = malloc(count / 4 * 3);
	if (out == NULL) return NULL;
	unsigned char *pos = out;

	char block[4];
	count = 0;
	int pad = 0;
	for (int i = 0; i < inLen; i++) {
		char tmp = dtable[in[i]];
		if (tmp == 0x80) continue;

		if (in[i] == '=') pad++;
		block[count] = tmp;
		count++;

		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;

			if (pad) {
				if (pad != 1 && pad != 2) {free(out); return NULL;}
				pos -= pad;
				break;
			}
		}
	}

	*outLen = pos - out;
	return out;
}
