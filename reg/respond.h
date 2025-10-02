#ifndef AEM_REG_RESPOND_H
#define AEM_REG_RESPOND_H

#include "../Common/AEM_KDF.h"

void setRegKey(const unsigned char baseKey[AEM_KDF_SUB_KEYLEN]);
void delRegKey(void);

#ifdef AEM_TLS
bool
#else
void
#endif
 respondClient(void);

#endif
