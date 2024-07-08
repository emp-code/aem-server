#ifdef AEM_TLS
#ifndef AEM_API_CLIENTTLS_H
#define AEM_API_CLIENTTLS_H

int tls_init(const unsigned char * const crt, const size_t lenCrt, const unsigned char * const key, const size_t lenKey, const unsigned char * const domain, const size_t lenDomain);
void tls_free(void);
int tls_connect(void);
int tls_peek(unsigned char * const buf, const size_t len);
int tls_recv(unsigned char * const buf, const size_t len);
int tls_send(const void * const buf, const size_t len);
void tls_disconnect(void);

#endif
#endif
