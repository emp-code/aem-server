#ifndef AEM_MTA_DELIVERY_H
#define AEM_MTA_DELIVERY_H

#include "Email.h"

#define SMTP_STORE_INERROR (-1)
#define SMTP_STORE_USRFULL (-2)
#define SMTP_STORE_MSGSIZE (-3)

void setSignKey(const unsigned char * const seed);
void delSignKey(void);

int deliverMessage(char to[AEM_SMTP_MAX_TO][32], const unsigned char toUpk[AEM_SMTP_MAX_TO][crypto_box_PUBLICKEYBYTES], const uint8_t toFlags[AEM_SMTP_MAX_TO], const int toCount, struct emailInfo * const email, const unsigned char * const original, const size_t lenOriginal);

#endif
