#include <string.h>

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

static bool needOriginal(const struct emailMeta * const meta) {
	for (int i = 0; i < meta->toCount; i++) {
		if ((meta->toFlags[i] & AEM_ADDR_FLAG_ORIGIN) != 0) return true;
	}

	return false;
}

int32_t deliverEmail(const struct emailMeta * const meta, struct emailInfo * const email, unsigned char * const src, size_t * const lenSrc) {
	getIpInfo(email);

	convertLineDots(src, lenSrc);

	// Add final CRLF for DKIM
	src[*lenSrc + 0] = '\r';
	src[*lenSrc + 1] = '\n';
	src[*lenSrc + 2] = '\0';
	(*lenSrc) += 2;

	unsigned char * const srcBr = /*needOriginal(meta) ? brCompress(src, lenSrc) :*/ NULL;

	processEmail(src, lenSrc, email);
	return storeMessage(meta, email, src, *lenSrc);
}
