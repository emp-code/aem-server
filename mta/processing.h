#ifndef AEM_PROCESSING_H
#define AEM_PROCESSING_H

#include "Email.h"

void processEmail(unsigned char *source, size_t * const lenSource, struct emailInfo * const email);

#endif
