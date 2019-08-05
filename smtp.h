#ifndef AEM_SMTP_H
#define AEM_SMTP_H

void respond_smtp(int sock, mbedtls_x509_crt * const srvcert, mbedtls_pk_context * const pkey, const unsigned char * const addrKey, const unsigned char * const seed, const char * const domain, const size_t lenDomain, const struct sockaddr_in * const clientAddr);

#endif
