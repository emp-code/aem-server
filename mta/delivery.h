#ifndef AEM_MTA_DELIVERY_H
#define AEM_MTA_DELIVERY_H

#include "Email.h"

void setSignKey(const unsigned char * const seed);
void deliverMessage(const char * const to, const size_t lenToTotal, const unsigned char * const msgBody, size_t lenMsgBody, struct emailInfo * const email);

#endif
