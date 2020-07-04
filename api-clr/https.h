#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

int tlsSetup(const unsigned char * const crtData, const size_t crtLen, const unsigned char * const keyData, const size_t keyLen);
void tlsFree(void);

void respondClient(int sock);

#endif
