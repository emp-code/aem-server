#ifndef AEM_HTTPS_GET_H
#define AEM_HTTPS_GET_H

void freeFiles(void);
void setResponse(const int type, unsigned char * const data, const size_t len);

void https_respond(mbedtls_ssl_context * const ssl, const char * const url, const size_t len);
void https_mtasts(mbedtls_ssl_context * const ssl);
void https_robots(mbedtls_ssl_context * const ssl);
void https_tsr(mbedtls_ssl_context * const ssl);

#endif
