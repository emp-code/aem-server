#include <string.h>

#include "../Global.h"
#include "memeq.h"

#include <sodium.h>

#include "x509_getCn.h"

static const unsigned char *x509_getCn(const unsigned char * const der, const size_t lenDer, size_t * const lenCn) {
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

int x509_getSubject(unsigned char * const out, size_t * const lenOut, const unsigned char * const pem, size_t lenPem) {
	if (lenPem < 100 || !memeq(pem, "-----BEGIN CERTIFICATE-----\n", 28)) return -1;
	const unsigned char * const pemEnd = memmem(pem + 28, lenPem - 28, "\n-----END CERTIFICATE-----", 26);
	if (pemEnd == NULL) return -2;

	lenPem = pemEnd - (pem + 28);
	unsigned char der[lenPem];
	size_t lenDer = 0;
	if (sodium_base642bin(der, lenPem, (const char*)pem + 28, lenPem, "\n", &lenDer, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) return -3;
	if (lenDer < 99) return -4;

	size_t lenIssuer;
	const unsigned char * const issuer = x509_getCn(der, lenDer, &lenIssuer);
	if (issuer == NULL) return -5;

	const unsigned char * const subject = x509_getCn(issuer, der + lenDer - issuer, lenOut);
	if (subject == NULL || *lenOut > AEM_MAXLEN_OURDOMAIN) return -6;

	memcpy(out, subject, *lenOut);
	return 0;
}
