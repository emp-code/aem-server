#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

int setDomain(const char * const newDomain, size_t len);

void respond_https(int sock, mbedtls_x509_crt * const srvcert, mbedtls_pk_context * const pkey);

#endif
