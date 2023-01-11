#ifndef AEM_RESPOND_H
#define AEM_RESPOND_H

int tlsSetup(void);
void tlsFree(void);

void setSignKey_mta(const unsigned char * const seed);
void delSignKey_mta(void);

void respondClient(int sock, const struct sockaddr_in * const clientAddr);

#endif
