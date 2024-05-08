#ifndef AEM_X509_GETCN_H
#define AEM_X509_GETCN_H

#include <stddef.h>

const unsigned char *x509_getCn(const unsigned char * const der, const size_t lenDer, size_t * const lenCn);

#endif
