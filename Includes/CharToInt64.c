#include <string.h>
#include <stdint.h>

__attribute__((warn_unused_result))
int64_t charToInt64(const void * const source) {
	if (source == NULL) return 0;

	int64_t i64;
	memcpy(&i64, source, 8);
	return i64;
}
