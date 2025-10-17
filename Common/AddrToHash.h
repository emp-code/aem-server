#ifndef AEM_ADDRTOHASH_H
#define AEM_ADDRTOHASH_H

#include "AEM_KDF.h"

void addressToHash_salt(const unsigned char baseKey[AEM_KDF_SUB_KEYLEN]);
void addressToHash_clear(void);
uint64_t addressToHash(const unsigned char * const addr32);

#endif
