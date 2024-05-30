#ifndef AEM_INCLUDES_MEMEQ_H
#define AEM_INCLUDES_MEMEQ_H

#include <stddef.h>

bool memeq(const void * const a, const void * const b, const size_t len);
bool memeq_anycase(const void * const a, const void * const b, const size_t len);
unsigned char *memcasemem(const unsigned char * const hay, const size_t lenHay, const void * const needle, const size_t lenNeedle);
unsigned char *mempbrk(const unsigned char * const hay, const size_t lenHay, const unsigned char needle[], const int lenNeedle);

#endif
