#ifndef AEM_MANAGER_H
#define AEM_MANAGER_H

#define AEM_PROCESSINFO_BYTES 65

int process_spawn(const int type, unsigned char * const launchKey, const unsigned char *key_forward);
void getProcessInfo(unsigned char * const out);
void setupManager(void);
void clearManager(void);

#endif
