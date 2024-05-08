#ifndef AEM_RESPOND_H
#define AEM_RESPOND_H

int tlsSetup(const unsigned char * const tls_crt_data, const size_t tls_crt_size, const unsigned char * const tls_key_data, const size_t tls_key_size);
void tlsFree(void);

void setSignKey_mta(const unsigned char * const seed);
void delSignKey_mta(void);

void respondClient(int sock, const struct sockaddr_in * const clientAddr);

#endif
