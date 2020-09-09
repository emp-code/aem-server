#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

int setHtml(const unsigned char * const data, const size_t len);
void freeHtml(void);

int tlsSetup(void);
void tlsFree(void);

void respondClient(int sock);

#endif
