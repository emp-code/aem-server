#ifndef AEM_SMTP_H
#define AEM_SMTP_H

int setDomain(const char * const new, const size_t len);
int tlsSetup(mbedtls_x509_crt * const tlsCert, mbedtls_pk_context * const tlsKey);
void tlsFree(void);

void respondClient(int sock, const struct sockaddr_in * const clientAddr);

#endif
