#ifndef AEM_EVPKEYS_H
#define AEM_EVPKEYS_H

#include "../Global.h"

struct evpKeys {
	unsigned char epk[AEM_EPK_KEYLEN]; // Encryption
	unsigned char usk[AEM_USK_KEYLEN]; // Signature
};

#endif
