#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

void respond_https(mbedtls_ssl_context *ssl, const uint32_t clientIp, const unsigned char seed[16]);

#endif
