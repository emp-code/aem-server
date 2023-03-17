#ifndef AEM_INCLUDES_TRIM_H
#define AEM_INCLUDES_TRIM_H

size_t charInvisible(const unsigned char * const c, const int len);
size_t charSpace(const unsigned char * const c, const int len);
void removeControlChars(unsigned char * const text, size_t * const len);
void cleanText(unsigned char * const text, size_t * const len);

#endif
