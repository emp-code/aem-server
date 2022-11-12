#include <stddef.h>
#include <string.h>
#include <syslog.h>

#include "../Common/Email.h"
#include "../Common/IntCom_Client.h"

static bool isIpBlacklisted(const uint8_t * const ip) {
	char dnsbl_domain[17 + AEM_MTA_DNSBL_LEN];
	sprintf(dnsbl_domain, "%u.%u.%u.%u."AEM_MTA_DNSBL, ip[3], ip[2], ip[1], ip[0]);

	unsigned char *dnsbl_ip = NULL;
	if (intcom(AEM_INTCOM_TYPE_ENQUIRY, AEM_ENQUIRY_A, (unsigned char*)dnsbl_domain, strlen(dnsbl_domain), &dnsbl_ip, 4) != 4) return false;

	const bool ret = (*((uint32_t*)dnsbl_ip) == 1);
	sodium_free(dnsbl_ip);
	return ret;
}

static bool greetingDomainMatchesIp(const unsigned char * const greet, const size_t lenGreet, const uint32_t ip) {
	unsigned char *greet_ip = NULL;
	if (intcom(AEM_INTCOM_TYPE_ENQUIRY, AEM_ENQUIRY_A, greet, lenGreet, &greet_ip, 4) != 4) return false;

	const bool ret = (ip == *((uint32_t*)greet_ip));
	sodium_free(greet_ip);
	return ret;
}

void getIpInfo(struct emailInfo * const email) {
	email->lenRvDns = 0;
	email->ccBytes[0] |= 31;
	email->ccBytes[1] |= 31;

	unsigned char *ipInfo = NULL;
	const int32_t lenIpInfo = intcom(AEM_INTCOM_TYPE_ENQUIRY, AEM_ENQUIRY_IP, (unsigned char*)&email->ip, 4, &ipInfo, 0);
	if (lenIpInfo < 1) return;
	if (lenIpInfo < 4) {sodium_free(ipInfo); return;}

	memcpy(email->ccBytes, ipInfo, 2);

	if (ipInfo[2] > 0) {
		email->lenRvDns = ipInfo[2];
		if (email->lenRvDns > 63) email->lenRvDns = 63;
		memcpy(email->rvDns, ipInfo + 4, email->lenRvDns);
	}

	if (ipInfo[3] > 0) {
		email->lenAuSys = ipInfo[3];
		if (email->lenAuSys > 63) email->lenAuSys = 63;
		memcpy(email->auSys, ipInfo + 4 + email->lenRvDns, email->lenAuSys);
	}

	sodium_free(ipInfo);

	email->ipMatchGreeting = greetingDomainMatchesIp(email->greet, email->lenGreet, email->ip);
	email->ipBlacklisted = isIpBlacklisted((uint8_t*)&email->ip);
}
