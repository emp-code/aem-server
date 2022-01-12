#ifndef AEM_DNS_PROTOCOL_H
#define AEM_DNS_PROTOCOL_H

#define AEM_DNS_RECORDTYPE_A      256 //  1; (const unsigned char[]) {0x00, 0x01}
#define AEM_DNS_RECORDTYPE_CNAME 1280 // 16; (const unsigned char[]) {0x00, 0x05}
#define AEM_DNS_RECORDTYPE_PTR   3072 // 12; (const unsigned char[]) {0x00, 0x0C}
#define AEM_DNS_RECORDTYPE_MX    3840 // 15; (const unsigned char[]) {0x00, 0x0F}
#define AEM_DNS_RECORDTYPE_TXT   4096 // 16; (const unsigned char[]) {0x00, 0x10}

int dnsCreateRequest(const uint16_t id, unsigned char * const rq, const unsigned char * const domain, const size_t lenDomain, const uint16_t queryType);
uint32_t dnsResponse_GetIp(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const domain, const size_t lenDomain, const uint16_t queryType);
int dnsResponse_GetNameRecord(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const domain, const size_t lenDomain, unsigned char * const result, size_t * const lenResult, const uint16_t queryType);

#endif
