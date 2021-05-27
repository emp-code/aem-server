#ifndef AEM_MTA_DELIVERY_H
#define AEM_MTA_DELIVERY_H

#include "Email.h"

void setSignKey(const unsigned char * const seed);
void delSignKey(void);

int deliverMessage(char to[AEM_SMTP_MAX_TO][32], const unsigned char toUpk[AEM_SMTP_MAX_TO][crypto_box_PUBLICKEYBYTES], const uint8_t toFlags[AEM_SMTP_MAX_TO], const int toCount, struct emailInfo * const email, const unsigned char * const original, const size_t lenOriginal, const bool brOriginal);

#endif
