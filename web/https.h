#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

#include "aem_file.h"

void respond_https(int sock, const char * const domain, const size_t lenDomain, const struct aem_fileSet * const fileSet);
void tlsFree(void);
int tlsSetup(mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey);

#endif
