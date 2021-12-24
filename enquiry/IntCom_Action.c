#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Common/ValidDomain.h"
#include "../Common/ValidIp.h"
#include "../Common/memeq.h"
#include "../Data/domain.h"
#include "../Data/internal.h"
#include "../Global.h"
#include "../api-common/Error.h"

#include "Geo.h"
#include "DNS.h"

#include "IntCom_Action.h"

int32_t conn_api(const uint8_t type, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	switch (type) {
		case AEM_ENQUIRY_MX: {
			if (!isValidDomain((char*)msg, lenMsg)) return AEM_INTCOM_RESPONSE_ERR; // AEM_API_ERR_MESSAGE_CREATE_EXT_INVALID_TO
			if (lenMsg == AEM_DOMAIN_LEN && memeq(msg, AEM_DOMAIN, AEM_DOMAIN_LEN)) return AEM_INTCOM_RESPONSE_ERR; // AEM_API_ERR_MESSAGE_CREATE_EXT_OURDOMAIN

			unsigned char mxDomain[256];
			int lenMxDomain = 0;
			const uint32_t ip = queryDns(msg, lenMsg, mxDomain, &lenMxDomain);
			if (lenMxDomain < 4 || lenMxDomain > 255) return AEM_INTCOM_RESPONSE_ERR;

			const uint16_t cc = getCountryCode(ip);
			const uint8_t ld = lenMxDomain;

			*res = sodium_malloc(7 + ld);
			if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;
			memcpy(*res, (unsigned char*)&ip, 4);
			memcpy(*res, (unsigned char*)&cc, 2);
			memcpy(*res, (unsigned char*)&ld, 1);
			memcpy(*res, mxDomain, ld);
			return 7 + ld;
		}

		default: syslog(LOG_ERR, "Invalid command: %u", type);
	}

	return AEM_INTCOM_RESPONSE_ERR;
}

int32_t conn_mta(const uint8_t type, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	switch (type) {
		case AEM_ENQUIRY_IP: {
			if (lenMsg != 5) return AEM_INTCOM_RESPONSE_ERR;

			const uint32_t ip = *((uint32_t*)msg);
			if (validIp(ip) == 1) return AEM_INTCOM_RESPONSE_ERR;

			*res = sodium_malloc(260); // 2 + 2 + 128 + 128
			if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;

			const uint16_t cc = getCountryCode(ip);
			memcpy(*res, (unsigned char*)&cc, 2);

			int lenPtr = 0;
			getPtr(ip, *res + 4, &lenPtr);
			if (lenPtr < 0) lenPtr = 0;

			size_t lenAsn = 0;
			getIpAsn(ip, *res + 4 + lenPtr, &lenAsn);
			if (lenAsn > 63) lenAsn = 63;

			(*res)[2] = lenPtr;
			(*res)[3] = lenAsn;

			return 4 + lenPtr + lenAsn;
		}

		case AEM_ENQUIRY_A: {
			if (!isValidDomain((char*)msg, lenMsg)) return AEM_INTCOM_RESPONSE_ERR;

			const uint32_t ip = queryDns_a(msg, lenMsg);

			*res = sodium_malloc(4);
			if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;
			memcpy(*res, (unsigned char*)&ip, 4);
			return 4;
		}

		case AEM_ENQUIRY_DKIM: {
			const unsigned char * const slash = memchr(msg, '/', lenMsg);
			if (slash == NULL) return AEM_INTCOM_RESPONSE_ERR;

			unsigned char dkimRecord[1024];
			int lenDkimRecord = 0;

			queryDns_dkim(msg, slash - msg, slash + 1, (msg + lenMsg) - (slash + 1), dkimRecord, &lenDkimRecord);
			if (lenDkimRecord < 1) return AEM_INTCOM_RESPONSE_ERR;
			*res = sodium_malloc(lenDkimRecord);
			if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;
			memcpy(*res, dkimRecord, lenDkimRecord);
			return lenDkimRecord;
		}

		default: syslog(LOG_ERR, "Invalid command: %u", type);
	}

	return AEM_INTCOM_RESPONSE_ERR;
}
