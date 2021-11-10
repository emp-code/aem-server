#include "memeq.h"

#include <ctype.h>

bool memeq(const void * const a, const void * const b, const size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (((const unsigned char * const)a)[i] != ((const unsigned char * const)b)[i]) return false;
	}

	return true;
}

bool memeq_anycase(const void * const a, const void * const b, const size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (tolower(((const unsigned char * const)a)[i]) != tolower(((const unsigned char * const)b)[i])) return false;
	}

	return true;
}

const unsigned char *memcasemem(const unsigned char * const hay, const size_t lenHay, const void * const needle, const size_t lenNeedle) {
	for (size_t i = 0; i < lenHay; i++) {
		bool found = true;

		for (size_t j = 0; j < lenNeedle; j++) {
			if (i + j >= lenHay) return NULL;

			if (tolower(hay[i + j]) != tolower(((const unsigned char * const)needle)[j])) {
				found = false;
				break;
			}
		}

		if (found) return hay + i;
	}

	return NULL;
}

const unsigned char *mempbrk(const unsigned char * const hay, const size_t lenHay, const unsigned char needle[], const int lenNeedle) {
	for (size_t i = 0; i < lenHay; i++) {
		for (int j = 0; j < lenNeedle; j++) {
			if (hay[i] == needle[j]) return hay + i;
		}
	}

	return NULL;
}
