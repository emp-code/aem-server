#ifndef AEM_API_MESSAGEID_H
#define AEM_API_MESSAGEID_H

#include <stdint.h>

void setMsgIdKey(const unsigned char * const src);
void delMsgIdKey(void);
void genMsgId(char * const out, const uint32_t ts, const uint16_t uid, const unsigned char * const addr32, const bool hex);

#endif
