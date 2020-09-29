#ifndef AEM_CREATESOCKET_H
#define AEM_CREATESOCKET_H

#include <stdbool.h>

int createSocket(const int port, const bool loopback, const time_t rcvTimeout, const time_t sndTimeout);

#endif
