#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#include "../Global.h"
#include "../Common/ValidDomain.h"
#include "../Common/ValidIp.h"
#include "../Common/memeq.h"

#include "Geo.h"
#include "DNS.h"

#include "IntCom_Action.h"

int32_t conn_api(const uint8_t type, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	switch (type) {
		case AEM_ENQUIRY_MX: {
			if (!isValidDomain((const char*)msg, lenMsg)) return AEM_INTCOM_RESPONSE_ERR; // AEM_API_ERR_MESSAGE_CREATE_EXT_INVALID_TO
//			if (lenMsg == AEM_DOMAIN_LEN && memeq(msg, AEM_DOMAIN, AEM_DOMAIN_LEN)) return AEM_INTCOM_RESPONSE_ERR; // AEM_API_ERR_MESSAGE_CREATE_EXT_OURDOMAIN
			*res = malloc(2048);
			if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;
			bzero(*res, 2048);

// [4] IP
// [2] CC
// [128] MxDomain
// [128] ASN
// [128] RDNS

			// IP, CC, MxDomain
			size_t lenMxDomain = 0;
			const uint32_t ip = queryDns_mx(msg, lenMsg, *res + 6, &lenMxDomain);
			if (lenMxDomain < 4 || lenMxDomain > 127) {free(*res); return AEM_INTCOM_RESPONSE_ERR;}
			memcpy(*res, (const unsigned char*)&ip, 4);

			const uint16_t cc = getCountryCode(ip);
			memcpy(*res + 4, (const unsigned char*)&cc, 2);

			// ASN
			size_t lenAsn = 0;
			getIpAsn(ip, *res + 134, &lenAsn); // 6 + 128
			if (lenAsn > 127) (*res)[261] = 0; // 134 + 127

			// RDNS (PTR)
			size_t lenPtr = 0;
			getPtr(ip, *res + 262, &lenPtr);
			if (lenPtr > 127) (*res)[389] = 0; // 262 + 127

			return 390; // 6 + (128 * 3)
		}

		default: syslog(LOG_ERR, "Invalid command: %u", type);
	}

	return AEM_INTCOM_RESPONSE_ERR;
}

int32_t conn_dlv(const uint8_t type, const unsigned char * const msg, const size_t lenMsg, unsigned char **res) {
	switch (type) {
		case AEM_ENQUIRY_IP: {
			if (lenMsg != 4) return AEM_INTCOM_RESPONSE_ERR;

			const uint32_t ip = *((const uint32_t*)msg);
			if (validIp(ip) == 1) return AEM_INTCOM_RESPONSE_ERR;

			*res = malloc(260); // 2 + 2 + 128 + 128
			if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;

			const uint16_t cc = getCountryCode(ip);
			memcpy(*res, (const unsigned char*)&cc, 2);

			size_t lenPtr = 0;
			getPtr(ip, *res + 4, &lenPtr);

			size_t lenAsn = 0;
			getIpAsn(ip, *res + 4 + lenPtr, &lenAsn);
			if (lenAsn > 63) lenAsn = 63;

			(*res)[2] = lenPtr;
			(*res)[3] = lenAsn;

			return 4 + lenPtr + lenAsn;
		}

		case AEM_ENQUIRY_A: {
			if (!isValidDomain((const char*)msg, lenMsg)) return AEM_INTCOM_RESPONSE_ERR;

			const uint32_t ip = queryDns_a(msg, lenMsg);

			*res = malloc(4);
			if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;
			memcpy(*res, (const unsigned char*)&ip, 4);
			return 4;
		}

		case AEM_ENQUIRY_DKIM: {
			const unsigned char * const slash = memchr(msg, '/', lenMsg);
			if (slash == NULL) return AEM_INTCOM_RESPONSE_ERR;

			unsigned char dkimRecord[1024];
			size_t lenDkimRecord = 0;
			queryDns_dkim(msg, slash - msg, slash + 1, (msg + lenMsg) - (slash + 1), dkimRecord, &lenDkimRecord);
			if (lenDkimRecord < 1) return AEM_INTCOM_RESPONSE_ERR;

			*res = malloc(lenDkimRecord + 1);
			if (*res == NULL) return AEM_INTCOM_RESPONSE_ERR;
			memcpy(*res, dkimRecord, lenDkimRecord);
			return lenDkimRecord + 1;
		}

		default: syslog(LOG_ERR, "Invalid command: %u", type);
	}

	return AEM_INTCOM_RESPONSE_ERR;
}
