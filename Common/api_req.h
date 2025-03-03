#ifndef AEM_API_REQ_H
#define AEM_API_REQ_H

#include <stdint.h>

union aem_req {
	struct {
		// Plaintext
		uint64_t binTs: 42;

		// Encrypted
		uint64_t cmd: 6;
		uint64_t flags: 8;
		uint64_t unused_1: 8;
		unsigned char unused_2[AEM_API_REQ_DATA_LEN + crypto_onetimeauth_BYTES];
	} n;

	struct {
		unsigned char unused_1[7];
		unsigned char data[AEM_API_REQ_DATA_LEN];
		unsigned char mac[crypto_onetimeauth_BYTES];
		unsigned char unused_2;
	} c;
};

#endif
