#ifndef AEM_PROCESSING_H
#define AEM_PROCESSING_H

void prepareHeaders(char *msg, size_t *lenMsg);
void trimSpace(char * const text, size_t * const len);
void removeSpaceEnd(char * const text, size_t * const len);
void trimLinebreaks(char * const text, size_t * const len);

void decodeEncodedWord(char * const data, size_t * const lenData);
void unfoldHeaders(char * const data, size_t * const lenData);
void decodeMessage(char ** const msg, size_t * const lenMsg);

#endif
