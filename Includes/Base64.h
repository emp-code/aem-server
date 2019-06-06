#ifndef INCLUDES_B64DEC_H
#define INCLUDES_B64DEC_H

unsigned char *b64Decode(const unsigned char *src, size_t srcLen, size_t *outLen);
unsigned char *b64Encode(const unsigned char *src, size_t srcLen, size_t *outLen);

#endif
