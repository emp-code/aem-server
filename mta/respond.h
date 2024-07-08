#ifndef AEM_RESPOND_H
#define AEM_RESPOND_H

int tls_init(const unsigned char * const crt, const size_t lenCrt, const unsigned char * const key, const size_t lenKey, const unsigned char * const domain, const size_t lenDomain);
void tls_free(void);

void respondClient(int sock, const struct sockaddr_in * const clientAddr);

#endif
