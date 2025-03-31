// binTs: 42-bit millisecond timestamp covering years 2025 to 2164

#include <math.h>
#include <time.h>

#include "../Global.h"

#include "binTs.h"

uint64_t getBinTs(void) {
	struct timespec t;
	clock_gettime(CLOCK_REALTIME, &t);
	return (t.tv_sec * 1000) + lrint((double)t.tv_nsec / 1000000) - AEM_BINTS_BEGIN;
}
