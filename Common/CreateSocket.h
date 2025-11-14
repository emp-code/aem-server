#ifndef AEM_CREATESOCKET_H
#define AEM_CREATESOCKET_H

#ifdef AEM_UDS
#ifdef AEM_API
void setUdsId(const unsigned char newId);
#endif
int createSocket(void);
#else
int createSocket(const time_t rcvTimeout, const time_t sndTimeout);
#endif

#endif
