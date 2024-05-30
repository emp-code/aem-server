#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/Email.h"
#include "../IntCom/Client.h"

#include "format.h"

#include "store.h"

int32_t storeMessage(const struct emailMeta * const meta, struct emailInfo * const email, unsigned char * const srcBr, const size_t lenSrcBr) {
	if (email->attachCount > 31) email->attachCount = 31;
	int32_t deliveryStatus = AEM_INTCOM_RESPONSE_OK;

	for (int i = 0; i < meta->toCount; i++) {
		if (meta->toUid[i] >= AEM_USERCOUNT) continue;

		email->lenEnvTo = strlen(meta->to[i]);
		if (email->lenEnvTo > 63) email->lenEnvTo = 63;
		memcpy(email->envTo, meta->to[i], email->lenEnvTo);

		size_t lenMsg = 0;
		unsigned char *msg = makeExtMsg(email, &lenMsg, (meta->toFlags[i] & AEM_ADDR_FLAG_ALLVER) != 0);
		if (msg == NULL || lenMsg < 1 || lenMsg % 16 != 0) {
			if (msg != NULL) free(msg);
			syslog(LOG_ERR, "makeExtMsg failed (%zu)", lenMsg);
			deliveryStatus = AEM_INTCOM_RESPONSE_ERR;
			continue;
		}

		uint16_t parentId = 0;
		int32_t stoRet = intcom(AEM_INTCOM_SERVER_STO, meta->toUid[i], msg, lenMsg, NULL, 0);
		if (stoRet < -1 * (UINT16_MAX + 1)) {
			deliveryStatus = AEM_INTCOM_RESPONSE_ERR;
			syslog(LOG_ERR, "Failed sending to Storage: %d", stoRet);
		} else parentId = stoRet + (UINT16_MAX + 1);

		sodium_memzero(msg, lenMsg);
		free(msg);

		// Store attachments, if requested
		if ((meta->toFlags[i] & AEM_ADDR_FLAG_ATTACH) != 0) {
			for (int j = 0; j < email->attachCount; j++) {
				memcpy(email->attachment[j] + AEM_ENVELOPE_RESERVED_LEN + 6, &parentId, sizeof(uint16_t));

				stoRet = intcom(AEM_INTCOM_SERVER_STO, meta->toUid[i], email->attachment[j], email->lenAttachment[j], NULL, 0);
				if (stoRet < -1 * (UINT16_MAX + 1)) {
					deliveryStatus = AEM_INTCOM_RESPONSE_ERR;
					syslog(LOG_ERR, "Failed sending to Storage: %d", stoRet);
				}
			}
		}

		// Store original, if requested
		if (srcBr != NULL && lenSrcBr > 0 && (meta->toFlags[i] & AEM_ADDR_FLAG_ORIGIN) != 0) {
			memcpy(srcBr + AEM_ENVELOPE_RESERVED_LEN + 6, &parentId, sizeof(uint16_t));
			intcom(AEM_INTCOM_SERVER_STO, meta->toUid[i], srcBr, lenSrcBr, NULL, 0); // Ignore failure
		}
	}

	return deliveryStatus;
}
