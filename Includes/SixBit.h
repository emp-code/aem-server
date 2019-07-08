#ifndef AEM_INCLUDES_SIXBIT_H
#define AEM_INCLUDES_SIXBIT_H

char *sixBitToText(const char *source, const size_t lenSource);
unsigned char *textToSixBit(const char *source, const size_t lenSource);
size_t lenToSixBit(const size_t len);

#endif
