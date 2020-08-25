#ifndef AEM_HTTPS_POST_H
#define AEM_HTTPS_POST_H

#include <sodium.h>

void setApiKey(const unsigned char * const seed);
void setSigKey(const unsigned char * const seed);

void setAccountPid(const pid_t pid);
void setStoragePid(const pid_t pid);
void setEnquiryPid(const pid_t pid);

int aem_api_init(void);
void aem_api_free(void);

int aem_api_prepare(const unsigned char * const pubkey, const bool ka);
int aem_api_process(const unsigned char * const box, size_t lenBox, unsigned char ** const response_p);

#endif
