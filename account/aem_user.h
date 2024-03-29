#ifndef AEM_AEMUSER_H
#define AEM_AEMUSER_H

#include "../Global.h"

struct aem_user {
	unsigned char upk[crypto_box_PUBLICKEYBYTES];
	unsigned char info; // & 3 = level; & 4 = unused; >> 3 = addresscount
	unsigned char private[AEM_LEN_PRIVATE];
	unsigned char addrFlag[AEM_ADDRESSES_PER_USER];
	uint64_t addrHash[AEM_ADDRESSES_PER_USER];
};

#endif
