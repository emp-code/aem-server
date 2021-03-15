#include <ctype.h>
#include <string.h>

#include "ValidDomain.h"

#include "ValidEmail.h"

bool isValidEmail(const char * const email) {
	const int lenEmail = strlen(email);
	if (lenEmail < 6 || lenEmail > 127) return false;

	// Local part
	int lenLocal = 0;

	for (;lenLocal < lenEmail; lenLocal++) {
		if (isalnum(email[lenLocal])) continue;
		if (lenLocal > 0 && (email[lenLocal] == '-' || email[lenLocal] == '+' || email[lenLocal] == '_' || (email[lenLocal] == '.' && email[lenLocal - 1] != '.'))) continue;
		if (email[lenLocal] == '@') break;
		return false;
	}

	if (lenLocal < 1 || lenLocal > 64) return false;

	if (email[lenLocal] != '@') return false;

	return (isValidDomain(email + lenLocal + 1, lenEmail - lenLocal - 1));
}
