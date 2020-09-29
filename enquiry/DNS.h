#ifndef AEM_DNS_H
#define AEM_DNS_H

void dns_freeTls(void);
int dns_setupTls(void);

uint32_t queryDns(const unsigned char * const domain, const size_t lenDomain);

#endif
