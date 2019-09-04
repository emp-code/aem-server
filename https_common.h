#ifndef AEM_HTTPS_COMMON_H
#define AEM_HTTPS_COMMON_H

void sendData(mbedtls_ssl_context * const ssl, const char * const data, const size_t lenData);

#endif
