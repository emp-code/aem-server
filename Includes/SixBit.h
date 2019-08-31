#ifndef AEM_INCLUDES_SIXBIT_H
#define AEM_INCLUDES_SIXBIT_H

#include <stdbool.h>

#define AEM_ADDRESS_HEXCHARS "acdeghilmnorstuw"

int addr2bin(const char * const source, const size_t len, unsigned char * const target);
bool isNormalBinAddress(const unsigned char * const source);

#endif
