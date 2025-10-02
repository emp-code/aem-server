#ifndef AEM_API_REQ_H
#define AEM_API_REQ_H

#include <stdint.h>

union aem_req {
	struct {
		uint64_t binTs: 42;
		uint64_t cmd: 4;
		uint64_t flags: 2;
		uint64_t unused_1: 16;
		unsigned char unused_2[40];
	} n;

	struct {
		unsigned char unused_1[6];
		unsigned char data[20];
		unsigned char mac[16];
		unsigned char unused_2[6];
	} c;
};

#endif
