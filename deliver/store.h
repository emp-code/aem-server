#ifndef AEM_STORE_H
#define AEM_STORE_H

#include "../Common/Email.h"

int32_t storeMessage(const struct emailMeta * const meta, struct emailInfo * const email, unsigned char * const srcBr, const size_t lenSrcBr);

#endif
