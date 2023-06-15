#ifndef AEM_HTTPS_POST_H
#define AEM_HTTPS_POST_H

#include <sodium.h>

void setApiKeys(const unsigned char baseKey[crypto_kdf_KEYBYTES]);

int aem_api_init(void);
void aem_api_free(void);

int32_t aem_api_prepare(const unsigned char * const upk, const bool ka);
int aem_api_process(const unsigned char * const box, size_t lenBox, unsigned char ** const response_p);

#endif
