#ifndef AEM_DNS_PROTOCOL_H
#define AEM_DNS_PROTOCOL_H

#define AEM_DNS_RECORDTYPE_A   (const unsigned char[]) {0x00, 0x01}
#define AEM_DNS_RECORDTYPE_PTR (const unsigned char[]) {0x00, 0x0C}
#define AEM_DNS_RECORDTYPE_MX  (const unsigned char[]) {0x00, 0x0F}
#define AEM_DNS_RECORDTYPE_TXT (const unsigned char[]) {0x00, 0x10}

int dnsCreateRequest(const uint16_t id, unsigned char * const rq, unsigned char * const question, size_t * const lenQuestion, const unsigned char * const domain, const size_t lenDomain, const unsigned char queryType[2]);
uint32_t dnsResponse_GetIp(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const question, const size_t lenQuestion);
int dnsResponse_GetNameRecord(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const question, const size_t lenQuestion, unsigned char * const result, int * const lenResult, const unsigned char queryType[2]);

#endif
