#ifndef AEM_DNS_PROTOCOL_H
#define AEM_DNS_PROTOCOL_H

#define AEM_DNS_RECORDTYPE_A   (const unsigned char[]) {0x00, 0x01}
#define AEM_DNS_RECORDTYPE_MX  (const unsigned char[]) {0x00, 0x0F}

int dnsCreateRequest(const uint16_t id, unsigned char * const rq, unsigned char * const question, size_t * const lenQuestion, const unsigned char * const domain, const size_t lenDomain, const unsigned char queryType[2]);
uint32_t dnsResponse_GetIp(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const question, const size_t lenQuestion);
int dnsResponse_GetMx(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const question, const size_t lenQuestion, unsigned char * const mxDomain, int * const lenMxDomain);

#endif
