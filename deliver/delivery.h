#ifndef AEM_DELIVERY_H
#define AEM_DELIVERY_H

#include "../Common/Email.h"

void setSignKey(const unsigned char * const seed);
void delSignKey(void);

int deliverMessage(struct emailMeta * const meta, struct emailInfo * const email, const unsigned char * const src, const size_t lenSrc);

#endif
