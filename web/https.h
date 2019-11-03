#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

void respond_https(int sock);
void tlsFree(void);
int tlsSetup(mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey);

#endif
