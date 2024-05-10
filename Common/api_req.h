#ifndef AEM_API_REQ_H
#define AEM_API_REQ_H

#include <stdint.h>

struct aem_req {
	// Plaintext
	uint64_t binTs: 40;
	uint64_t uid: 12;

	// Encrypted
	uint64_t cmd: 4;
	uint64_t flags: 4;
	uint64_t unused: 4;

	unsigned char data[AEM_API_REQ_DATA_LEN];

	// Authentication
	unsigned char mac[crypto_onetimeauth_BYTES];
};

#endif
