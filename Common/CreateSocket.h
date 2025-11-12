#ifndef AEM_CREATESOCKET_H
#define AEM_CREATESOCKET_H

#ifdef AEM_UDS
void setUdsId(char newId);
int createSocket(void);
#else
int createSocket(const time_t rcvTimeout, const time_t sndTimeout);
#endif

#endif
