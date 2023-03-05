#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <syslog.h>

#include "../Global.h"

#include "IO.h"

#include "IntCom_Action.h"

int32_t conn_api(const uint8_t type, const unsigned char *msg, size_t lenMsg, unsigned char **res) {
	if (lenMsg < crypto_box_PUBLICKEYBYTES) {syslog(LOG_WARNING, "Rejected: missing UPK"); return AEM_INTCOM_RESPONSE_ERR;}

	const int num = userNumFromUpk(msg);
	if (num < 0) {syslog(LOG_WARNING, "Rejected: non-existing UPK"); return AEM_INTCOM_RESPONSE_NOTEXIST;}

	msg += crypto_box_PUBLICKEYBYTES;
	lenMsg -= crypto_box_PUBLICKEYBYTES;

	switch (type) {
		case AEM_API_ACCOUNT_BROWSE: return api_account_browse(num, res);
		case AEM_API_ACCOUNT_CREATE: return api_account_create(num, msg, lenMsg);
		case AEM_API_ACCOUNT_DELETE: return api_account_delete(num, msg, lenMsg);
		case AEM_API_ACCOUNT_UPDATE: return api_account_update(num, msg, lenMsg);

		case AEM_API_ADDRESS_CREATE: return api_address_create(num, msg, lenMsg, res);
		case AEM_API_ADDRESS_DELETE: return api_address_delete(num, msg, lenMsg);
		case AEM_API_ADDRESS_UPDATE: return api_address_update(num, msg, lenMsg);

		case AEM_API_PRIVATE_UPDATE: return api_private_update(num, msg, lenMsg);
		case AEM_API_SETTING_LIMITS: return api_setting_limits(num, msg, lenMsg);

		// Internal
		case AEM_API_INTERNAL_ADRPK: return api_internal_adrpk(num, msg, lenMsg, res);
		case AEM_API_INTERNAL_EXIST: return AEM_INTCOM_RESPONSE_OK; // Existence verified by userNumFromUpk()
		case AEM_API_INTERNAL_LEVEL: return api_internal_level(num);
		case AEM_API_INTERNAL_MYADR: return api_internal_myadr(num, msg, lenMsg);
		case AEM_API_INTERNAL_UINFO: return api_internal_uinfo(num, res);
		case AEM_API_INTERNAL_PUBKS: return api_internal_pubks(num, res);

		default: syslog(LOG_ERR, "Invalid command: %u", type);
	}

	return AEM_INTCOM_RESPONSE_ERR;
}

int32_t conn_mta(const uint8_t type, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	if (lenMsg != 10) return AEM_INTCOM_RESPONSE_ERR;

	switch (type) {
		case AEM_MTA_GETUPK_NORMAL: return mta_getUpk(msg, false, res);
		case AEM_MTA_GETUPK_SHIELD: return mta_getUpk(msg, true, res);

		default: syslog(LOG_ERR, "Invalid command: %u", type);
	}

	return AEM_INTCOM_RESPONSE_ERR;
}
