#include <stdlib.h>
#include <string.h>

#include "Base64.h"

static const unsigned char b64Table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned char *b64Encode(const unsigned char *src, size_t srcLen, size_t *outLen) {
	size_t olen = ((srcLen * 4) / 3) + 5;
	if (olen < srcLen) return NULL; // Source too large

	unsigned char *out = malloc(olen);
	if (out == NULL) return NULL;

	const unsigned char *end = src + srcLen;
	const unsigned char *in = src;
	unsigned char* pos = out;

	while (end - in >= 3) {
		*pos++ = b64Table[in[0] >> 2];
		*pos++ = b64Table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = b64Table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = b64Table[in[2] & 0x3f];
		in += 3;
	}

	if (end - in) {
		*pos++ = b64Table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = b64Table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = b64Table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
			*pos++ = b64Table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
	}

	*pos = '\0';
	if (outLen != NULL) *outLen = pos - out;
	return out;
}

unsigned char *b64Decode(const unsigned char *src, size_t srcLen, size_t *outLen) {
	unsigned char dtable[256];
	memset(dtable, 0x80, 256);
	for (int i = 0; i < 66; i++) dtable[b64Table[i]] = (unsigned char)i;
	dtable['='] = 0;

	size_t count = 0;
	for (int i = 0; i < srcLen; i++) {
		if (dtable[src[i]] != 0x80) count++;
	}

	if (count == 0 || count % 4) return NULL;

	size_t olen = count / 4 * 3;
	unsigned char *out = malloc(olen);
	if (out == NULL) return NULL;
	unsigned char *pos = out;

	int pad = 0;
	count = 0;
	for (int i = 0; i < srcLen; i++) {
		unsigned char block[4];
		unsigned char tmp = dtable[src[i]];
		if (tmp == 0x80) continue;

		if (src[i] == '=') pad++;
		block[count] = tmp;
		count++;

		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;

			if (pad) {
				if (pad != 1 && pad != 2) {
					/* Invalid padding */
					free(out);
					return NULL;
				}

				pos -= pad;
				break;
			}
		}
	}

	if (outLen != NULL) *outLen = pos - out;
	return out;
}
