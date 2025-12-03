#include <string.h>
#include <syslog.h>
#include <brotli/encode.h>

#include "../Common/Message.h"

#include "ipInfo.h"
#include "processing.h"
#include "store.h"

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

static unsigned char *makeSrcBr(const unsigned char * const input, const size_t lenInput, size_t * const lenOutput, const uint64_t binTs) {
	if (lenInput > 1048576) return NULL; // 1 MiB

	const char * const fn = "src.eml.br";
	const size_t lenFn = 10;

	*lenOutput = lenInput + 300; // Compressed version can be slightly larger
	unsigned char * const output = malloc(AEM_MSG_HDR_SZ + 3 + lenFn + *lenOutput);
	if (output == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}

	aem_msg_init(output, AEM_MSG_TYPE_UPL, binTs);
	output[AEM_MSG_HDR_SZ] = (lenFn - 1) | 128; // 128: Attachment
	// 2 bytes: ParentID
	memcpy(output + AEM_MSG_HDR_SZ + 3, fn, lenFn);

	if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS, BROTLI_MODE_TEXT, lenInput, input, lenOutput, output + AEM_MSG_HDR_SZ + 3 + lenFn) == BROTLI_FALSE) {
		syslog(LOG_ERR, "Failed Brotli compression");
		free(output);
		return NULL;
	}

	*lenOutput += AEM_MSG_HDR_SZ + 3 + lenFn;
	return output;
}

static bool needOriginal(const struct emailMeta * const meta) {
	for (int i = 0; i < meta->toCount; i++) {
		if ((meta->toFlags[i] & AEM_ADDR_FLAG_ORIGIN) != 0) return true;
	}

	return false;
}

int32_t deliverEmail(const struct emailMeta * const meta, struct emailInfo * const email, unsigned char * const src, size_t lenSrc) {
	getIpInfo(email);

	convertLineDots(src, &lenSrc);
	email->attachCount = 0;

	// Add final CRLF
	src[lenSrc + 0] = '\r';
	src[lenSrc + 1] = '\n';
	src[lenSrc + 2] = '\0';
	lenSrc += 2;

	size_t lenSrcBr = 0;
	unsigned char * const srcBr = needOriginal(meta) ? makeSrcBr(src + 1, lenSrc - 1, &lenSrcBr, email->binTs) : NULL;

	email->head = NULL;
	email->body = NULL;

	processEmail(src, &lenSrc, email);

	const int32_t ret = storeMessage(meta, email, srcBr, lenSrcBr);
	if (srcBr != NULL) free(srcBr);

	if (email->head != NULL) free(email->head);
	if (email->body != NULL && email->body != src) free(email->body);
	for (int i = 0; i < email->attachCount; i++) {
		free(email->attachment[i]);
	}

	return ret;
}
