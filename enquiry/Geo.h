#ifndef AEM_GEO_H
#define AEM_GEO_H

#include <stdint.h>

#define AEM_ENQUIRY_GEO_ERROR 7967

uint16_t getCountryCode(const uint32_t ip);
void getIpAsn(const uint32_t ip, unsigned char * const result, size_t * const lenAsn);

#endif
