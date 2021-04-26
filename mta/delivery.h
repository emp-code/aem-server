#ifndef AEM_MTA_DELIVERY_H
#define AEM_MTA_DELIVERY_H

#include "Email.h"

#define SMTP_STORE_INERROR (-1)
#define SMTP_STORE_USRFULL (-2)
#define SMTP_STORE_MSGSIZE (-3)

void setSignKey(const unsigned char * const seed);
void delSignKey(void);

int deliverMessage(char to[][32], const int toCount, struct emailInfo * const email);

#endif
