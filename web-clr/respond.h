#ifndef AEM_RESPOND_H
#define AEM_RESPOND_H

int tlsSetup(void);
void tlsFree(void);

void respondClient(int sock);

#endif
