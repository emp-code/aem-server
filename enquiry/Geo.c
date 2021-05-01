#include <ctype.h> // for isupper()
#include <netinet/in.h>
#include <string.h> // for memcpy()
#include <syslog.h>

#include <maxminddb.h>

#include "Geo.h"

uint16_t getCountryCode(const uint32_t ip) {
	MMDB_s mmdb;
	int status = MMDB_open("GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb);
	if (status != MMDB_SUCCESS) {
		syslog(LOG_ERR, "getCountryCode: MMDB_open failed: %s", MMDB_strerror(status));
		return AEM_ENQUIRY_GEO_ERROR;
	}

	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ip;

	MMDB_lookup_result_s mmdb_result = MMDB_lookup_sockaddr(&mmdb, (struct sockaddr*)&sa, &status);
	if (status != MMDB_SUCCESS) {
		syslog(LOG_ERR, "getCountryCode: MMDB_lookup_sockaddr failed: %s", MMDB_strerror(status));
		MMDB_close(&mmdb);
		return AEM_ENQUIRY_GEO_ERROR;
	}

	uint16_t res = AEM_ENQUIRY_GEO_ERROR;
	if (mmdb_result.found_entry) {
		MMDB_entry_data_s entry_data;
		status = MMDB_get_value(&mmdb_result.entry, &entry_data, "country", "iso_code", NULL);

		if (status == MMDB_SUCCESS && isupper(entry_data.utf8_string[0]) && isupper(entry_data.utf8_string[1])) {
			memcpy(&res, (unsigned char[]){
				entry_data.utf8_string[0] - 'A',
				entry_data.utf8_string[1] - 'A',
			}, 2);
		} else syslog(LOG_ERR, "getCountryCode: MMDB_get_value failed: %s", MMDB_strerror(status));
	} else syslog(LOG_ERR, "getCountryCode: No entry");

	MMDB_close(&mmdb);
	return res;
}

void getIpAsn(const uint32_t ip, unsigned char * const result, size_t * const lenAsn) {
	MMDB_s mmdb;
	int status = MMDB_open("GeoLite2-ASN.mmdb", MMDB_MODE_MMAP, &mmdb);
	if (status != MMDB_SUCCESS) {
		syslog(LOG_ERR, "getCountryCode: MMDB_open failed: %s", MMDB_strerror(status));
		return;
	}

	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ip;

	MMDB_lookup_result_s mmdb_result = MMDB_lookup_sockaddr(&mmdb, (struct sockaddr*)&sa, &status);
	if (status != MMDB_SUCCESS) {
		syslog(LOG_ERR, "getIpAsn: MMDB_lookup_sockaddr failed: %s", MMDB_strerror(status));
		MMDB_close(&mmdb);
		return;
	}

	if (mmdb_result.found_entry) {
		MMDB_entry_data_s entry_data;
		status = MMDB_get_value(&mmdb_result.entry, &entry_data, "autonomous_system_organization", NULL);

		if (status == MMDB_SUCCESS && entry_data.data_size > 0 && entry_data.data_size <= 63) {
			memcpy(result, entry_data.utf8_string, entry_data.data_size);
			*lenAsn = entry_data.data_size;
		} else {
			syslog(LOG_ERR, "getIpAsn: MMDB_get_value failed: %s", MMDB_strerror(status));
		}
	} else syslog(LOG_ERR, "getIpAsn: No entry");

	MMDB_close(&mmdb);
}
