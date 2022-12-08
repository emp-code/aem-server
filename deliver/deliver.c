#include <string.h>
#include <syslog.h>

#include <brotli/encode.h>

#include "store.h"
#include "ipInfo.h"
#include "processing.h"

#include "deliver.h"

static void convertLineDots(unsigned char * const src, size_t * const lenSrc) {
	unsigned char *c = memmem(src, *lenSrc, "\r\n..", 4);

	while (c != NULL) {
		c += 2;
		const size_t offset = (c + 1) - src;

		memmove(c, c + 1, *lenSrc - offset);
		(*lenSrc)--;

		c = memmem(src + offset, *lenSrc - offset, "\r\n..", 4);
	}
}

unsigned char *brCompress(const unsigned char * const input, const size_t lenInput, size_t * const lenOutput) {
	*lenOutput = lenInput + 100; // Compressed version can be slightly larger
	unsigned char * const output = malloc(*lenOutput);
	if (output == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}

	if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_DEFAULT_MODE, lenInput, input, lenOutput, output) == BROTLI_FALSE) {
		syslog(LOG_ERR, "Failed Brotli compression");
		free(output);
		return NULL;
	} else {
		return output;
	}
}

static bool needOriginal(const struct emailMeta * const meta) {
	for (int i = 0; i < meta->toCount; i++) {
		if ((meta->toFlags[i] & AEM_ADDR_FLAG_ORIGIN) != 0) return true;
	}

	return false;
}

int32_t deliverEmail(const struct emailMeta * const meta, struct emailInfo * const email, unsigned char * const src, size_t * const lenSrc) {
	getIpInfo(email);

	convertLineDots(src, lenSrc);
	email->attachCount = 0;

	size_t lenSrcBr = 0;
	unsigned char * const srcBr = needOriginal(meta) ? brCompress(src, *lenSrc, &lenSrcBr) : NULL;

	// Add final CRLF for DKIM
	src[*lenSrc + 0] = '\r';
	src[*lenSrc + 1] = '\n';
	src[*lenSrc + 2] = '\0';
	(*lenSrc) += 2;

	email->head = NULL;
	email->body = NULL;

	processEmail(src, lenSrc, email);

	const int32_t ret = storeMessage(meta, email, srcBr, lenSrcBr);
	if (srcBr != NULL) free(srcBr);

	if (email->head != NULL) free(email->head);
	if (email->body != NULL && email->body != src) free(email->body);
	for (int i = 0; i < email->attachCount; i++) {
		free(email->attachment[i]);
	}

	return ret;
}
