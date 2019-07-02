#ifndef AEM_INTMSG_H
#define AEM_INTMSG_H

#include <sodium.h>

#define AEM_INTMSG_HEADERSIZE 41 // Note that HeadBox is a total (AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES) bytes

unsigned char *aem_intMsg_makeBoxSet(unsigned char *binFrom, unsigned char *binTo, unsigned char senderInfo, const char *bodyText, size_t *bodyLen, unsigned char pk[crypto_box_PUBLICKEYBYTES]);

#endif
