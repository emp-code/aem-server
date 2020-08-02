#ifndef AEM_CREATESOCKET
#define AEM_CREATESOCKET

#include <stdbool.h>

int createSocket(const int port, const bool loopback, const time_t rcvTimeout, const time_t sndTimeout);

#endif
