#ifndef AEM_HTTPS_GET_H
#define AEM_HTTPS_GET_H

#define AEM_FILETYPE_CSS  1
#define AEM_FILETYPE_HTML 2
#define AEM_FILETYPE_JSAE 3
#define AEM_FILETYPE_JSMN 4

void freeFiles(void);
int loadFile(const int type);

void https_respond(mbedtls_ssl_context * const ssl, const char * const url, const size_t len);
void https_mtasts(mbedtls_ssl_context * const ssl);
void https_robots(mbedtls_ssl_context * const ssl);
void https_tsr(mbedtls_ssl_context * const ssl);

#endif
