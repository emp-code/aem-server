#ifndef AEM_INTMSG_H
#define AEM_INTMSG_H

#include <sodium.h>

unsigned char *aem_intMsg_makeHeadBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const uint8_t senderMemberLevel, const char *adrFrom, const char *adrTo);
unsigned char *aem_intMsg_makeBodyBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const char *bodyText, size_t *bodyLen);

#endif
