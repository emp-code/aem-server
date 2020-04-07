#ifndef AEM_HTTPS_POST_H
#define AEM_HTTPS_POST_H

#include <sodium.h>

#define AEM_HTTPS_POST_SIZE 8192 // 8 KiB
#define AEM_HTTPS_POST_BOXED_SIZE (crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + AEM_HTTPS_POST_SIZE + 2 + crypto_box_MACBYTES)

void setApiKey(const unsigned char * const newKey);
void setAccessKey_account(const unsigned char * const newKey);
void setAccessKey_storage(const unsigned char * const newKey);

bool pubkeyExists(const unsigned char * const pubkey);

int https_post(mbedtls_ssl_context * const ssl, const char * const url, const unsigned char * const post, const bool ka);

int aem_api_init(void);
void aem_api_free(void);

#endif
