#ifndef AEM_SMTP_H
#define AEM_SMTP_H

int setDomain(const char * const new, const size_t len);

void respond_smtp(int sock, mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey, const struct sockaddr_in * const clientAddr);

#endif
