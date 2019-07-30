#ifndef AEM_MESSAGE_H
#define AEM_MESSAGE_H

#include <sodium.h>

#define AEM_HEADBOX_SIZE 41 // Encrypted: (AEM_HEADBOX_SIZE + crypto_box_SEALBYTES)

unsigned char *makeMsg_Int(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char *binFrom, const unsigned char *binTo, const unsigned char senderInfo, const char *bodyText, size_t * const bodyLen);
unsigned char *makeMsg_Ext(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char *binTo, const uint32_t ip, const int32_t cs, const char *bodyText, size_t * const bodyLen);

#endif
