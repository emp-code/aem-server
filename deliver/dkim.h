#ifndef AEM_MTA_DKIM_H
#define AEM_MTA_DKIM_H

#include "../Common/Email.h"

int verifyDkim(struct emailInfo * const email, const unsigned char * const src, const size_t lenSrc);

#endif
