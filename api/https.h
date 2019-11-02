#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

void respond_https(int sock, mbedtls_x509_crt * const srvcert, mbedtls_pk_context * const pkey, const unsigned char * const ssk, const char * const domain, const size_t lenDomain);

#endif
