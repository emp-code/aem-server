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
#include "../Data/domain.h"
#include "../Data/internal.h"
#include "../Global.h"

#include "Geo.h"
#include "DNS.h"

#include "ClientAction.h"

void conn_api(const int sock, const unsigned char * const dec, const size_t lenDec) {
	switch (dec[0]) {
		case AEM_ENQUIRY_MX: {
			if (!isValidDomain((char*)dec + 1, lenDec - 1)) break;
			if (lenDec - 1 == AEM_DOMAIN_LEN && memcmp(dec + 1, AEM_DOMAIN, AEM_DOMAIN_LEN) == 0) break;

			unsigned char mxDomain[256];
			int lenMxDomain = 0;
			const uint32_t ip = queryDns(dec + 1, lenDec - 1, mxDomain, &lenMxDomain);
			const uint16_t cc = getCountryCode(ip);

			if (lenMxDomain > 4 && lenMxDomain < 256) {
				send(sock, &ip, 4, 0);
				send(sock, &cc, 2, 0);
				send(sock, &lenMxDomain, sizeof(int), 0);
				send(sock, mxDomain, lenMxDomain, 0);
			}
		break;}

		default: syslog(LOG_ERR, "Invalid command: %u", dec[0]);
	}
}

void conn_mta(const int sock, const unsigned char * const dec, const size_t lenDec) {
	switch (dec[0]) {
		case AEM_ENQUIRY_IP: {
			if (lenDec != 5) break;
			const uint32_t ip = *((uint32_t*)(dec + 1));
			if (validIp(ip) == 1) break;

			unsigned char resp[129];
			const uint16_t cc = getCountryCode(ip);
			memcpy(resp, &cc, 2);

			int lenPtr = 0;
			getPtr(ip, resp + 2, &lenPtr);

			send(sock, &resp, (lenPtr < 1) ? 2 : 2 + lenPtr, 0);
		break;}

		case AEM_ENQUIRY_A: {
			if (!isValidDomain((char*)dec + 1, lenDec - 1)) break;

			const uint32_t ip = queryDns_a(dec + 1, lenDec - 1);
			send(sock, &ip, 4, 0);
		break;}

		case AEM_ENQUIRY_DKIM: {
			const unsigned char * const slash = memchr(dec + 1, '/', lenDec - 1);
			if (slash == NULL) break;

			unsigned char dkimRecord[1024];
			int lenDkimRecord = 0;

			queryDns_dkim(dec + 1, slash - (dec + 1), slash + 1, (dec + lenDec) - (slash + 1), dkimRecord, &lenDkimRecord);
			if (lenDkimRecord > 0) send(sock, dkimRecord, lenDkimRecord, 0);
		break;}

		default: syslog(LOG_ERR, "Invalid command: %u", dec[0]);
	}
}