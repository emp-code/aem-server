#ifndef AEM_API_MESSAGEID_H
#define AEM_API_MESSAGEID_H

#include <stdbool.h>
#include <stdint.h>

void setMsgIdKey(const unsigned char * const src);
void genMsgId(char * const out, const uint32_t ts, const unsigned char * const upk, const bool b64);

#endif
