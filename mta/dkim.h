#ifndef AEM_MTA_DKIM_H
#define AEM_MTA_DKIM_H

#include "Email.h"

void verifyDkim(struct emailInfo * const email, const unsigned char * const src, const size_t lenSrc);

#endif
