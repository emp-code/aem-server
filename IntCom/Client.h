#ifndef AEM_INTCOM_CLIENT_H
#define AEM_INTCOM_CLIENT_H

#include <stdint.h>

#include <sodium.h>

#include "KeyBundle.h"

void intcom_setKeys_client(const unsigned char newKeys[AEM_INTCOM_SERVER_COUNT][crypto_aead_aegis256_KEYBYTES]);

int32_t intcom(const aem_intcom_server_t intcom_server, const uint32_t operation, const unsigned char * const msg, const size_t lenMsg, unsigned char ** const out, const int32_t expectedLenOut);

#if defined(AEM_API) || defined(AEM_MTA) || defined(AEM_REG)
void setAccountPid(const pid_t pid);
#endif
#if defined(AEM_API) || defined(AEM_DELIVER)
void setEnquiryPid(const pid_t pid);
#endif
void setStoragePid(const pid_t pid);

#endif
