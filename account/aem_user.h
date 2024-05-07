#ifndef AEM_AEMUSER_H
#define AEM_AEMUSER_H

#include "../Common/AEM_KDF.h"
#include "../Global.h"

#define AEM_USERCOUNT 4096

#define AEM_UAK_TYPE_URL_AUTH  0
#define AEM_UAK_TYPE_URL_DATA 32LLU
#define AEM_UAK_TYPE_BODY_REQ 64LLU
#define AEM_UAK_TYPE_BODY_RES 96LLU

struct aem_user {
	unsigned char uak[AEM_KDF_KEYSIZE]; // User Access Key
	unsigned char epk[X25519_PKBYTES]; // Envelope Public Key
	unsigned char lastBinTs[5]; // To prevent replay attacks
	unsigned char private[AEM_LEN_PRIVATE];

	uint8_t level: 2;
	uint8_t unused_value: 1;
	uint8_t addrCount: 5;

	unsigned char addrFlag[AEM_ADDRESSES_PER_USER];
	uint64_t addrHash[AEM_ADDRESSES_PER_USER];
};

#endif
