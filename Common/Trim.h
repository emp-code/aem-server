#ifndef AEM_INCLUDES_TRIM_H
#define AEM_INCLUDES_TRIM_H

void removeControlChars(unsigned char * const text, size_t * const len);
void convertLineDots(unsigned char * const text, size_t * const len);
void convertNbsp(unsigned char * const text, size_t * const len);
void trimSpace(unsigned char * const text, size_t * const len);
void removeSpaceEnd(unsigned char * const text, size_t * const len);
void removeSpaceBegin(unsigned char * const text, size_t * const len);
void trimLinebreaks(unsigned char * const text, size_t * const len);

void trimBegin(unsigned char * const text, size_t * const len);
void trimEnd(const unsigned char * const text, size_t * const len);

#endif
