#include <ctype.h>
#include <stddef.h>

#include "ValidDomain.h"

bool isValidDomain(const char * const domain, const int lenDomain) {
	if (domain == NULL || lenDomain < 4 || lenDomain > 127) return false;

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
