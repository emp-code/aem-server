#ifndef AEM_INCLUDES_TRIM_H
#define AEM_INCLUDES_TRIM_H

void removeControlChars(unsigned char * const text, size_t * const len);
void cleanText(unsigned char * const text, size_t * const len);

#endif
