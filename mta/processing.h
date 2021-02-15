#ifndef AEM_PROCESSING_H
#define AEM_PROCESSING_H

#include "Email.h"

#define MTA_PROCESSING_CTE_NONE 0
#define MTA_PROCESSING_CTE_B64 1
#define MTA_PROCESSING_CTE_QP 2

int getHeaders(unsigned char * const data, size_t * const lenData, struct emailInfo * const email);
void moveHeader(unsigned char * const data, size_t * const lenData, const char * const needle, const size_t lenNeedle, unsigned char * const target, uint8_t * const lenTarget, const size_t limit);
void decodeEncodedWord(unsigned char * const data, size_t * const lenData);
unsigned char *decodeCte(const int cte, const unsigned char * const src, size_t * const lenSrc);
void convertToUtf8(unsigned char ** const src, size_t * const lenSrc, const char * const charset);
char *getCharset(const char *ct);
unsigned char* getBound(const char * const src, size_t * const lenBound);
unsigned char *decodeMp(const unsigned char * const src, size_t *outLen, struct emailInfo * const email, unsigned char * const bound0, const size_t lenBound0);

#endif
