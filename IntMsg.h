#ifndef AEM_INTMSG_H
#define AEM_INTMSG_H

#include <sodium.h>

#define AEM_INTMSG_HEADERSIZE 41 // Note that HeadBox is a total (AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES) bytes

unsigned char *aem_intMsg_makeHeadBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char senderInfo, const unsigned char adrFrom[18], const unsigned char adrTo[18]);
unsigned char *aem_intMsg_makeBodyBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const char *bodyText, size_t *bodyLen);

#endif
