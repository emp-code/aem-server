#ifndef AEM_SMTP_H
#define AEM_SMTP_H

int tlsSetup(void);
void tlsFree(void);
void setSignKey_mta(const unsigned char * const seed);

void respondClient(int sock, const struct sockaddr_in * const clientAddr);

#endif
