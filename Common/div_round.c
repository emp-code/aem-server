#include "div_round.h"

long long div_floor(const long long a, const long long b) {
	return (a - (a % b)) / b;
}

long long div_near(const long long a, const long long b) {
	return div_floor(a, b) + ((((a % b) / (long double)b) < 0.5) ? 0 : 1);
}

long long div_ceil(const long long a, const long long b) {
        return (a % b == 0) ? a / b : div_floor(a, b) + 1;
}
