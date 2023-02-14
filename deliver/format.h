#ifndef AEM_FORMAT_H
#define AEM_FORMAT_H

#include "../Common/Email.h"

#include <stdbool.h>
#include <stddef.h>

void setSignKey(const unsigned char * const baseKey);
void delSignKey(void);

unsigned char *makeAttachment(const unsigned char * const upk, unsigned char * const att, const size_t lenAtt, const uint32_t ts, const unsigned char parentId[16], size_t * const lenEnc);
unsigned char *makeExtMsg(struct emailInfo * const email, const unsigned char * const upk, size_t * const lenOut, const bool allVer);

#endif
