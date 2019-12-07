#ifndef AEM_PROCESSING_H
#define AEM_PROCESSING_H

void removeControlChars(unsigned char * const text, size_t * const len);
void tabsToSpaces(char * const text, const size_t len);
void trimSpace(char * const text, size_t * const len);
void removeSpaceEnd(char * const text, size_t * const len);
void trimLinebreaks(char * const text, size_t * const len);

void decodeEncodedWord(char * const data, size_t * const lenData);
void unfoldHeaders(char * const data, size_t * const lenData);
void decodeMessage(char ** const msg, size_t * const lenMsg);

#endif
