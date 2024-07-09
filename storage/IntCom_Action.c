#include <syslog.h>

#include <sodium.h>

#include "../Global.h"

#include "IO.h"

#include "IntCom_Action.h"

int32_t conn_acc(const uint32_t operation, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	switch (operation) {
		case AEM_ACC_STORAGE_AMOUNT: return acc_storage_amount(res);
		case AEM_ACC_STORAGE_CREATE: return acc_storage_create(msg, lenMsg);
		case AEM_ACC_STORAGE_DELETE: return acc_storage_delete(msg, lenMsg);
//		case AEM_ACC_STORAGE_LEVELS: return acc_storage_levels(msg, lenMsg);
		case AEM_ACC_STORAGE_LIMITS: return acc_storage_limits(msg, lenMsg);
	}

	syslog(LOG_ERR, "conn_acc(): Invalid op: %u", operation);
	return AEM_INTCOM_RESPONSE_ERR;
}

int32_t conn_api(const uint32_t operation, unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	if (operation == AEM_INTCOM_OP_BROWSE_NEW) return api_message_browse(msg, lenMsg, res, true);
	if (operation == AEM_INTCOM_OP_BROWSE_OLD) return api_message_browse(msg, lenMsg, res, false);
	if (operation < AEM_USERCOUNT) return storage_write(msg, lenMsg, operation);
	if (operation - AEM_USERCOUNT < AEM_USERCOUNT && lenMsg == 2) return storage_delete(operation - AEM_USERCOUNT, *(uint16_t*)msg);

	syslog(LOG_ERR, "conn_api(): Invalid op: %u", operation);
	return AEM_INTCOM_RESPONSE_ERR;
}

int32_t conn_dlv(const uint32_t operation, unsigned char * const msg, const size_t lenMsg) {
	if (operation < AEM_USERCOUNT) return storage_write(msg, lenMsg, operation);

	syslog(LOG_ERR, "conn_dlv(): Invalid op: %u", operation);
	return AEM_INTCOM_RESPONSE_ERR;
}
