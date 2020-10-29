#ifndef AEM_INCLUDES_VALIDUTF8_H
#define AEM_INCLUDES_VALIDUTF8_H

#include <stdbool.h>
#include <stddef.h>

bool isValidUtf8(const unsigned char * const src, const size_t len);

#endif
