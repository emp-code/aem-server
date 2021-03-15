#ifndef AEM_PROCESSING_H
#define AEM_PROCESSING_H

#include "Email.h"

#define MTA_PROCESSING_CTE_NONE 0
#define MTA_PROCESSING_CTE_B64 1
#define MTA_PROCESSING_CTE_QP 2

void processEmail(unsigned char *source, size_t * const lenSource, struct emailInfo * const email);

#endif
