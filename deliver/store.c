#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/Addr32.h"
#include "../Common/Email.h"
#include "../Common/memeq.h"
#include "../IntCom/Client.h"

#include "format.h"

#include "store.h"

int32_t storeMessage(const struct emailMeta * const meta, struct emailInfo * const email, unsigned char * const srcBr, const size_t lenSrcBr) {
	if (meta->toCount < 1) {syslog(LOG_ERR, "deliverMessage(): Empty"); return AEM_INTCOM_RESPONSE_ERR;}
	if (email->attachCount > 31) email->attachCount = 31;

	int32_t deliveryStatus = AEM_INTCOM_RESPONSE_OK;

	for (int i = 0; i < meta->toCount; i++) {
		email->lenEnvTo = strlen(meta->to[i]);
		if (email->lenEnvTo > 63) email->lenEnvTo = 63;
		memcpy(email->envTo, meta->to[i], email->lenEnvTo);

		size_t lenEnc = 0;
		unsigned char *enc = makeExtMsg(email, meta->toUpk[i], &lenEnc, (meta->toFlags[i] & AEM_ADDR_FLAG_ALLVER) != 0);
		if (enc == NULL || lenEnc < 1 || lenEnc % 16 != 0) {
			if (enc != NULL) free(enc);
			syslog(LOG_ERR, "makeExtMsg failed (%zu)", lenEnc);
			deliveryStatus = AEM_INTCOM_RESPONSE_ERR;
			continue;
		}

		unsigned char msgId[16];
		memcpy(msgId, enc + crypto_box_PUBLICKEYBYTES, 16);

		if (intcom(AEM_INTCOM_SERVER_STO, 0, enc, lenEnc, NULL, 0) != AEM_INTCOM_RESPONSE_OK) {
			deliveryStatus = AEM_INTCOM_RESPONSE_ERR;
		}

		sodium_memzero(enc, lenEnc);
		free(enc);

		// Store attachments, if requested
		if ((meta->toFlags[i] & AEM_ADDR_FLAG_ATTACH) != 0) {
			for (int j = 0; j < email->attachCount; j++) {
				enc = makeAttachment(meta->toUpk[i], email->attachment[j], email->lenAttachment[j], email->timestamp, msgId, &lenEnc);

				if (enc == NULL || intcom(AEM_INTCOM_SERVER_STO, 0, enc, lenEnc, NULL, 0) != AEM_INTCOM_RESPONSE_OK) {
					deliveryStatus = AEM_INTCOM_RESPONSE_ERR;
				}

				if (enc != NULL) {
					sodium_memzero(enc, lenEnc);
					free(enc);
				}
			}
		}

		// Store original, if requested
		if (srcBr != NULL && lenSrcBr > 0 && (meta->toFlags[i] & AEM_ADDR_FLAG_ORIGIN) != 0) {
			enc = makeAttachment(meta->toUpk[i], srcBr, lenSrcBr, email->timestamp, msgId, &lenEnc);
			if (enc != NULL) {
				intcom(AEM_INTCOM_SERVER_STO, 0, enc, lenEnc, NULL, 0); // Ignore failure
				sodium_memzero(enc, lenEnc);
				free(enc);
			}
		}
	}

	return deliveryStatus;
}
