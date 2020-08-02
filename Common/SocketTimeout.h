#ifndef AEM_SOCKETTIMEOUT_H
#define AEM_SOCKETTIMEOUT_H

int setSocketTimeout(const int sock, const time_t rcvSec, const time_t sndSec);

#endif
