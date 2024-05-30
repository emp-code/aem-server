#ifndef AEM_INCLUDES_VALIDUTF8_H
#define AEM_INCLUDES_VALIDUTF8_H

#include <stddef.h>

int validUtf8(const unsigned char * const src, const size_t len, const bool allowControl);
bool isValidUtf8(const unsigned char * const src, const size_t len);
void filterUtf8(unsigned char * const src, const size_t len, const bool allowControl);

#endif
