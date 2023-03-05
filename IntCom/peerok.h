#ifndef AEM_INTCOM_PEEROK_H
#define AEM_INTCOM_PEEROK_H

#include <stdbool.h>
#include <sys/types.h>

bool peerOk(const int sock
	#ifdef AEM_PEEROK_CLIENT
	, const pid_t peerPid
	#endif
);

#endif
