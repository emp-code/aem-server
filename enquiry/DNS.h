#ifndef AEM_DNS
#define AEM_DNS

void dns_freeTls(void);
int dns_setupTls(void);

uint32_t queryDns(const unsigned char * const domain, const size_t lenDomain);

#endif
