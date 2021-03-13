#ifndef AEM_MTA_DELIVERY_H
#define AEM_MTA_DELIVERY_H

#include "Email.h"

void setSignKey(const unsigned char * const seed);
void delSignKey(void);

void deliverMessage(char to[][32], const int toCount, struct emailInfo * const email);

#endif
