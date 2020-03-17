#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

int setDomain(const char * const src, const size_t len);
int setHtml(const unsigned char * const data, const size_t len);

void freeHtml(void);

void tlsFree(void);
int tlsSetup(mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey);

void respond_https(int sock);

#endif
