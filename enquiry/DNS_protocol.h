#ifndef AEM_DNS_PROTOCOL_H
#define AEM_DNS_PROTOCOL_H

int dnsCreateRequest(const uint16_t id, unsigned char * const rq, unsigned char * const question, size_t * const lenQuestion, const unsigned char * const domain, const size_t lenDomain, const bool isMx);
uint32_t dnsResponse_GetIp(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const question, const size_t lenQuestion);
int dnsResponse_GetMx(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const question, const size_t lenQuestion, unsigned char * const mxDomain, int * const lenMxDomain);

#endif
