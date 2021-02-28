#ifndef AEM_DNS_H
#define AEM_DNS_H

void tlsFree(void);
int tlsSetup(void);

uint32_t queryDns(const unsigned char * const domain, const size_t lenDomain, unsigned char * const mxDomain, int * const lenMxDomain);
uint32_t queryDns_a(const unsigned char * const domain, const size_t lenDomain);
void queryDns_dkim(const unsigned char * const selector, const size_t lenSelector, const unsigned char * const domain, const size_t lenDomain, unsigned char * const dkimRecord, int * const lenDkimRecord);
int getPtr(const uint32_t ip, unsigned char * const ptr, int * const lenPtr);

#endif
