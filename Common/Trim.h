#ifndef AEM_INCLUDES_TRIM_H
#define AEM_INCLUDES_TRIM_H

void removeControlChars(unsigned char * const text, size_t * const len);
void convertNbsp(char * const text, size_t * const len);
void trimSpace(char * const text, size_t * const len);
void removeSpaceEnd(char * const text, size_t * const len);
void removeSpaceBegin(char * const text, size_t * const len);
void trimLinebreaks(char * const text, size_t * const len);
void trimEnd(const char * const text, size_t * const len);

#endif
