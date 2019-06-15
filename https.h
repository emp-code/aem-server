#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

#include "aem_file.h"

int respond_https(int sock, mbedtls_x509_crt *srvcert, mbedtls_pk_context *pkey, const uint32_t clientIp, const unsigned char seed[16], const struct aem_fileSet *fileSet, const char *domain, const size_t lenDomain);

#endif
