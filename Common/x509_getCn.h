#ifndef AEM_X509_GETCN_H
#define AEM_X509_GETCN_H

#include <stddef.h>

int x509_getSubject(unsigned char * const out, size_t * const lenOut, const unsigned char * const pem, size_t lenPem);

#endif
