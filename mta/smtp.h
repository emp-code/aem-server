#ifndef AEM_SMTP_H
#define AEM_SMTP_H

int tlsSetup(const unsigned char * const crtData, const size_t crtLen, const unsigned char * const keyData, const size_t keyLen);
void tlsFree(void);

void respondClient(int sock, const struct sockaddr_in * const clientAddr);

#endif
