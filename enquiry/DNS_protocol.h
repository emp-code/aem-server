#ifndef AEM_DNS_PROTOCOL_H
#define AEM_DNS_PROTOCOL_H

int dnsCreateRequest(unsigned char * const rq, const unsigned char * const domain, const size_t lenDomain, const bool mx);
int dnsResponse_GetMx(const unsigned char * const res, const int resLen, unsigned char * const mxDomain, int * const lenMxDomain);
uint32_t dnsResponse_GetIp(const unsigned char * const res, const int resLen);

#endif
