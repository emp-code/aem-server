#ifndef AEM_STORE_H
#define AEM_STORE_H

#include "../Common/Email.h"

void setSignKey(const unsigned char * const seed);
void delSignKey(void);

int32_t storeMessage(const struct emailMeta * const meta, struct emailInfo * const email, const unsigned char * const src, const size_t lenSrc);

#endif
