#ifndef AEM_CERT_H
#define AEM_CERT_H

#include <mbedtls/ssl.h>

uint8_t cert_getTlsInfo_type(const mbedtls_x509_crt * const cert);
uint8_t cert_getTlsInfo_name(const mbedtls_x509_crt * const cert, const unsigned char * const greet, const size_t lenGreet, unsigned char *envFr, size_t lenEnvFr, unsigned char *hdrFr, size_t lenHdrFr);

#endif
