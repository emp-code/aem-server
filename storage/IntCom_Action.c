#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "IO.h"

#include "../Data/internal.h"
#include "../Global.h"

#include "IntCom_Action.h"

int32_t conn_acc(const uint8_t type, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	switch (type) {
		case AEM_ACC_STORAGE_LIMITS: return acc_storage_limits(msg, lenMsg);
		case AEM_ACC_STORAGE_AMOUNT: return acc_storage_amount(res);
		case AEM_ACC_STORAGE_LEVELS: return acc_storage_levels(msg, lenMsg);
	}

	return AEM_INTCOM_RESPONSE_ERR;
}

int32_t conn_api(const uint8_t type, unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	switch (type) {
		case AEM_API_INTERNAL_ERASE: return api_internal_erase(msg, lenMsg);
		case AEM_API_MESSAGE_BROWSE: return api_message_browse(msg, lenMsg, res);
		case AEM_API_MESSAGE_DELETE: return api_message_delete(msg, lenMsg);
		case AEM_API_MESSAGE_UPLOAD: return storage_write(msg, lenMsg);
	}

	return AEM_INTCOM_RESPONSE_ERR;
}

int32_t conn_mta(const uint8_t type, unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	if (type == AEM_MTA_INSERT) return storage_write(msg, lenMsg);

	return AEM_INTCOM_RESPONSE_ERR;
}
