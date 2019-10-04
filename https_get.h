#ifndef AEM_HTTPS_GET_H
#define AEM_HTTPS_GET_H

void https_get(mbedtls_ssl_context * const ssl, const char * const url, const size_t lenUrl, const struct aem_fileSet * const fileSet, const char * const domain, const size_t lenDomain);
void https_mtasts(mbedtls_ssl_context * const ssl, const char * const domain, const int lenDomain);
void https_robots(mbedtls_ssl_context * const ssl);
void https_pubkey(mbedtls_ssl_context * const ssl, const unsigned char * const ssk);

#endif
