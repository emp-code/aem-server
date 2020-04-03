#ifndef AEM_INCLUDES_BASE64_H
#define AEM_INCLUDES_BASE64_H

#include <stdbool.h>

unsigned char *b64Decode(const unsigned char * const src, const size_t srcLen, size_t * const outLen);

#endif
