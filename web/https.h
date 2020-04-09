#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

int setHtml(const unsigned char * const data, const size_t len);
void freeHtml(void);

int setCertData(unsigned char * const crtData, const size_t crtLen, unsigned char * const keyData, const size_t keyLen);
int tlsSetup(void);
void tlsFree(void);

void respondClient(int sock);

#endif
