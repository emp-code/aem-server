#ifndef AEM_INCLUDES_TOUTF8_H
#define AEM_INCLUDES_TOUTF8_H

#include <stdbool.h>

bool isUtf8(const char * const charset);
unsigned char *toUtf8(const unsigned char * const input, const size_t lenInput, size_t * const lenOut, const char * const charset);

#endif
