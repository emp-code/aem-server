#include "memeq.h"

bool memeq(const void * const a, const void * const b, const size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (((unsigned char*)a)[i] != ((unsigned char*)b)[i]) return false;
	}

	return true;
}
