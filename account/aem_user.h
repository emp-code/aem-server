#ifndef AEM_AEMUSER_H
#define AEM_AEMUSER_H

#include "../Common/AEM_KDF.h"
#include "../Global.h"

#define AEM_USERCOUNT 4096

struct aem_user {
	unsigned char uak[AEM_KDF_UAK_KEYLEN]; // User API Key
	unsigned char usk[AEM_USK_KEYLEN]; // User Signature Key
	unsigned char epk[AEM_EPK_KEYLEN]; // Envelope Public Key
	unsigned char private[AEM_LEN_PRIVATE];

	unsigned char addrFlag[AEM_ADDRESSES_PER_USER];
	uint64_t addrHash[AEM_ADDRESSES_PER_USER];

	uint64_t lastBinTs: 42; // To prevent replay attacks
	uint64_t level: 2;
	uint64_t addrCount: 5;
	uint64_t unused_value: 15;
};

#endif
