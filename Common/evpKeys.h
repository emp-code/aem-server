#ifndef AEM_EVPKEYS_H
#define AEM_EVPKEYS_H

#include "../Global.h"

struct evpKeys {
	bool security;
	unsigned char pwk[AEM_PWK_KEYLEN];
	unsigned char psk[AEM_PSK_KEYLEN];
	unsigned char pqk[AEM_PQK_KEYLEN];
	unsigned char usk[AEM_USK_KEYLEN];
};

#endif
