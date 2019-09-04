#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

#include "aem_file.h"

void respond_https(int sock, mbedtls_x509_crt * const srvcert, mbedtls_pk_context * const pkey, const unsigned char * const ssk, const unsigned char * const addrKey, const char * const domain, const size_t lenDomain, const struct aem_fileSet * const fileSet);

#endif
