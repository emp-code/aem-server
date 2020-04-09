#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

int setCertData(unsigned char * const crtData, const size_t crtLen, unsigned char * const keyData, const size_t keyLen);
int tlsSetup(void);
void tlsFree(void);

void respondClient(int sock);

#endif
