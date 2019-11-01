#ifndef AEM_HTTPS_GET_H
#define AEM_HTTPS_GET_H

#include "aem_file.h"

void https_get(mbedtls_ssl_context * const ssl, const char * const url, const size_t lenUrl, const struct aem_fileSet * const fileSet);
void https_mtasts(mbedtls_ssl_context * const ssl);
void https_robots(mbedtls_ssl_context * const ssl);
void https_tsr(mbedtls_ssl_context * const ssl);

#endif
