#include "memeq.h"

#include <ctype.h>

bool memeq(const void * const a, const void * const b, const size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (((unsigned char*)a)[i] != ((unsigned char*)b)[i]) return false;
	}

	return true;
}

bool memeq_anycase(const void * const a, const void * const b, const size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (tolower(((unsigned char*)a)[i]) != tolower(((unsigned char*)b)[i])) return false;
	}

	return true;
}

const unsigned char *memcasemem(const unsigned char * const hay, const size_t lenHay, const void * const needle, const size_t lenNeedle) {
	for (size_t i = 0; i < lenHay; i++) {
		bool found = true;

		for (size_t j = 0; j < lenNeedle; j++) {
			if (i + j >= lenHay) return NULL;

			if (tolower(hay[i + j]) != tolower(((unsigned char*)needle)[j])) {
				found = false;
				break;
			}
		}

		if (found) return hay + i;
	}

	return NULL;
}
