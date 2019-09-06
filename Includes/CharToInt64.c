#include <string.h>
#include <stdint.h>

int64_t charToInt64(const void * const source) {
	if (source == NULL) return 0;

	int64_t i64;
	memcpy(&i64, source, 8);
	return i64;
}
