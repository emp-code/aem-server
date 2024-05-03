#ifndef AEM_FORMAT_H
#define AEM_FORMAT_H

#include "../Common/Email.h"

#include <stdbool.h>
#include <stddef.h>

unsigned char *makeAttachment(unsigned char * const att, const size_t lenAtt, const uint32_t ts, const unsigned char parentId[16]);
unsigned char *makeExtMsg(struct emailInfo * const email, size_t * const lenOut, const bool allVer);

#endif
