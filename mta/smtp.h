#ifndef AEM_SMTP_H
#define AEM_SMTP_H

int setCertData(unsigned char * const crtData, const size_t crtLen, unsigned char * const keyData, const size_t keyLen);
int tlsSetup();
void tlsFree(void);

void respondClient(int sock, const struct sockaddr_in * const clientAddr);

#endif
