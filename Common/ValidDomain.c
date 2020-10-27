#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include "ValidDomain.h"

bool isValidDomain(const char * const domain, const int lenDomain) {
	if (domain == NULL
	|| lenDomain < 4
	|| lenDomain > 127
	|| (lenDomain == 11 && memcmp(domain, "example.", 8) == 0 && ((memcmp(domain + 8, "com", 3) == 0) || (memcmp(domain + 8, "net", 3) == 0) || (memcmp(domain + 8, "org", 3) == 0)))
	) return false;

	int lastDot = 0;

	for (int i = 0; i < lenDomain; i++) {
		if (domain[i] == '.') lastDot = i;

		if (islower(domain[i]) || isdigit(domain[i]) ||
			(i > 0 && (
				   (domain[i] == '.' &&  isalnum(domain[i - 1]))
				|| (domain[i] == '-' && (isalnum(domain[i - 1]) || domain[i - 1] == '-'))
			))
		) continue;
		return false;
	}

	return (lastDot < lenDomain - 2); // (getTldLocation(domain, NULL) > 0)
}
