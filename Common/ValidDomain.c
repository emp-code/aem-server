#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include "ValidDomain.h"

static bool hasAlpha(const char * const c, const size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (islower(c[i])) return true;
	}

	return false;
}

bool isValidDomain(const char * const domain, const size_t lenDomain) {
	if (domain == NULL
	|| lenDomain < 4
	|| lenDomain > 127
	|| (lenDomain == 11 && memcmp(domain, "example.", 8) == 0 && ((memcmp(domain + 8, "com", 3) == 0) || (memcmp(domain + 8, "net", 3) == 0) || (memcmp(domain + 8, "org", 3) == 0)))
	) return false;

	size_t lastDot = 0;

	for (size_t i = 0; i < lenDomain; i++) {
		if (islower(domain[i]) || isdigit(domain[i])) continue;

		if (domain[i] == '.') {
			if (!hasAlpha(domain + lastDot, i - lastDot)) return false;
			lastDot = i;
		}

		if (i > 0 && (
			   (domain[i] == '.' && (isdigit(domain[i - 1]) || islower(domain[i - 1])))
			|| (domain[i] == '-' && (isdigit(domain[i - 1]) || islower(domain[i - 1]) || domain[i - 1] == '-'))
		)) continue;

		return false;
	}

	return (lastDot > 0 && lastDot < lenDomain - 2 && hasAlpha(domain + lastDot, lenDomain - lastDot));
}
