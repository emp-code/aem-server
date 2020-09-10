#ifndef AEM_MANAGER_H
#define AEM_MANAGER_H

void killAll(int sig);
void setMasterKey(const unsigned char newKey[crypto_secretbox_KEYBYTES]);
int loadFiles(void);
int receiveConnections(void);

#endif
