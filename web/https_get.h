#ifndef AEM_HTTPS_GET_H
#define AEM_HTTPS_GET_H

#define AEM_FILETYPE_CSS 1
#define AEM_FILETYPE_HTM 2
#define AEM_FILETYPE_JSA 3
#define AEM_FILETYPE_JSM 4

void freeFiles(void);
int setResponse(const int type, const unsigned char * const fileData, const size_t fileSize);

void https_respond(mbedtls_ssl_context * const ssl, const char * const url, const size_t len);
void https_mtasts(mbedtls_ssl_context * const ssl);
void https_robots(mbedtls_ssl_context * const ssl);
void https_tsr(mbedtls_ssl_context * const ssl);

#endif
