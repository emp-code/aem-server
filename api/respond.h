#ifndef AEM_RESPOND_H
#define AEM_RESPOND_H

#ifndef AEM_IS_ONION
int tlsSetup(void);
void tlsFree(void);
#endif

void respondClient(int sock);

#endif
