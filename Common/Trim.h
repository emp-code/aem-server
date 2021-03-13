#ifndef AEM_INCLUDES_TRIM_H
#define AEM_INCLUDES_TRIM_H

#include <stdbool.h>

void removeControlChars(unsigned char * const text, size_t * const len);
void cleanText(unsigned char * const text, size_t * const len, const bool removeControl);
void convertLineDots(unsigned char * const text, size_t * const len);

#endif
