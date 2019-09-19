#ifndef AEM_HTTPS_POST_H
#define AEM_HTTPS_POST_H

#define AEM_HTTPS_POST_SIZE 8192 // 8 KiB

void https_post(mbedtls_ssl_context * const ssl, const unsigned char * const ssk, const unsigned char * const addrKey, const char * const domain, const size_t lenDomain, const char * const url, const unsigned char * const post, const size_t lenPost);

#endif
