#ifndef AEM_HTTPS_H
#define AEM_HTTPS_H

int tlsSetup(void);
void tlsFree(void);

void respondClient(int sock);

#endif
