#include <stdbool.h>
#include <string.h>

#include <mbedtls/ssl.h>

#include "../Common/Email.h"
#include "../Common/memeq.h"

#include "cert.h"

uint8_t cert_getTlsInfo_type(const mbedtls_x509_crt * const cert) {
	if (cert == NULL) return AEM_EMAIL_CERT_TYPE_NONE;

	const size_t keyBits = mbedtls_pk_get_bitlen(&cert->pk);

	if (memeq(mbedtls_pk_get_name(&cert->pk), "RSA", 3)) {
		if      (keyBits >= 4096) return AEM_EMAIL_CERT_TYPE_RSA4K;
		else if (keyBits >= 2048) return AEM_EMAIL_CERT_TYPE_RSA2K;
		else if (keyBits >= 1024) return AEM_EMAIL_CERT_TYPE_RSA1K;
	} else if (memeq(mbedtls_pk_get_name(&cert->pk), "EC", 2)) {
		if      (keyBits >= 521) return AEM_EMAIL_CERT_TYPE_EC521;
		else if (keyBits >= 384) return AEM_EMAIL_CERT_TYPE_EC384;
		else if (keyBits >= 256) return AEM_EMAIL_CERT_TYPE_EC256;
	} else if (memeq(mbedtls_pk_get_name(&cert->pk), "EDDSA", 5)) return AEM_EMAIL_CERT_TYPE_EDDSA;

	return AEM_EMAIL_CERT_TYPE_NONE;
}

static void setEmailDomain(unsigned char ** const c, size_t * const len) {
	const unsigned char *at = memchr(*c, '@', *len);
	if (at == NULL) return;

	const size_t offset = (at + 1) - *c;
	*c += offset;
	*len -= offset;
}

uint8_t cert_getTlsInfo_name(const mbedtls_x509_crt * const cert, const unsigned char * const greet, const size_t lenGreet, unsigned char *envFr, size_t lenEnvFr, unsigned char *hdrFr, size_t lenHdrFr) {
	if (cert == NULL) return AEM_EMAIL_CERT_NAME_OTHER;

	setEmailDomain(&envFr, &lenEnvFr);
	setEmailDomain(&hdrFr, &lenHdrFr);

	bool firstDone = false;
	const mbedtls_asn1_sequence *s = &cert->subject_alt_names;

	while(1) {
		size_t lenName;
		const unsigned char *name;

		if (!firstDone) {
			lenName = cert->subject.val.len;
			name = cert->subject.val.p;
			firstDone = true;
		} else {
			if (s == NULL) break;
			lenName = s->buf.len;
			name = s->buf.p;
			s = s->next;
		}

		if (name == NULL || lenName < 4) continue; // a.bc

		if (memeq(name, "*.", 2)) { // Wildcard: remove the asterisk and see if the ends match
			lenName--;
			name++;

			if (lenName < lenHdrFr && memeq(hdrFr + lenHdrFr - lenName, name, lenName)) return AEM_EMAIL_CERT_NAME_HDRFR;
			if (lenName < lenEnvFr && memeq(envFr + lenEnvFr - lenName, name, lenName)) return AEM_EMAIL_CERT_NAME_ENVFR;
			if (lenName < lenGreet && memeq(greet + lenGreet - lenName, name, lenName)) return AEM_EMAIL_CERT_NAME_GREET;
		} else {
			if      (lenName == lenHdrFr && memeq(name, hdrFr, lenName)) return AEM_EMAIL_CERT_NAME_HDRFR;
			else if (lenName == lenEnvFr && memeq(name, envFr, lenName)) return AEM_EMAIL_CERT_NAME_ENVFR;
			else if (lenName == lenGreet && memeq(name, greet, lenName)) return AEM_EMAIL_CERT_NAME_GREET;
		}
	}

	return AEM_EMAIL_CERT_NAME_OTHER;
}
