#ifndef AEM_PROCESSING_H
#define AEM_PROCESSING_H

#include "../Common/Email.h"

void processEmail(unsigned char * const src, size_t * const lenSrc, struct emailInfo * const email);

#endif
