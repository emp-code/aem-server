#ifndef AEM_HTTPS_POST_H
#define AEM_HTTPS_POST_H

#include <sodium.h>

#define AEM_HTTPS_POST_SIZE 8192 // 8 KiB
#define AEM_HTTPS_POST_BOXED_SIZE (crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + AEM_HTTPS_POST_SIZE + crypto_box_MACBYTES)

void https_post(mbedtls_ssl_context * const ssl, const unsigned char * const ssk, const unsigned char * const addrKey, const char * const url, const unsigned char * const post);
void https_pubkey(mbedtls_ssl_context * const ssl, const unsigned char * const ssk);

#endif
