#include <string.h>

#include "x509_getCn.h"

const unsigned char *x509_getCn(const unsigned char * const der, const size_t lenDer, size_t * const lenCn) {
	size_t offset = 0;

	for(;;) {
		const unsigned char * const cn = memmem(der + offset, lenDer - offset, (unsigned char[]){0x06, 0x03, 0x55, 0x04, 0x03, 0x13}, 6);
		if (cn == NULL) break;
		offset = cn - der;

		if (cn - der < 10 || der + lenDer - cn < 10) continue;
		*lenCn = cn[6];
		if (*lenCn < 1) continue;

		if (
		   *(cn - 1) != *lenCn + 7
		|| *(cn - 2) != 0x30
		|| *(cn - 3) != *lenCn + 9
		|| *(cn - 4) != 0x31
		) continue;

		if ((int)*lenCn >= der + lenDer - cn) continue;

		bool fail = false;
		for (size_t i = 0; i < *lenCn; i++) {
			if (cn[7 + i] < 32 || cn[7 + i] >= 127) {
				fail = true;
				break;
			}
		}
		if (fail) continue;

		return cn + 7;
	}

	return NULL;
}
