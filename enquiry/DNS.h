#ifndef AEM_DNS_H
#define AEM_DNS_H

void tlsFree(void);
int tlsSetup(void);

uint32_t queryDns_a(const unsigned char * const domain, const size_t lenDomain);
uint32_t queryDns_mx(const unsigned char * const domain, const size_t lenDomain, unsigned char * const mxDomain, size_t * const lenMxDomain);
void queryDns_dkim(const unsigned char * const selector, const size_t lenSelector, const unsigned char * const domain, const size_t lenDomain, unsigned char * const dkimRecord, size_t * const lenDkimRecord);
int getPtr(const uint32_t ip, unsigned char * const ptr, size_t * const lenPtr);

#endif
