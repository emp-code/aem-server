#ifndef AEM_API_REQ_H
#define AEM_API_REQ_H

#define AEM_API_REQ_LEN 48
#define AEM_API_REQ_LEN_BASE64 64

#define AEM_API_REQ_DATA_LEN 24

#include <stdint.h>

struct aem_req {
	// Plaintext
	uint64_t binTs: 40;
	uint64_t uid: 12;

	// Encrypted
	uint64_t cmd: 4;
	uint64_t flags: 8;
	unsigned char data[AEM_API_REQ_DATA_LEN];

	// Authentication
	unsigned char mac[crypto_onetimeauth_BYTES];
};

#endif
