#ifndef AEM_FORMAT_H
#define AEM_FORMAT_H

#include "../Common/Email.h"

#include <stddef.h>

unsigned char *makeExtMsg(struct emailInfo * const email, size_t * const lenOut, const bool allVer);

#endif
