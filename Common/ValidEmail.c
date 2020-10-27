#include <ctype.h>
#include <string.h>

#include "ValidEmail.h"

bool isValidEmail(const char * const email) {
	const int lenEmail = strlen(email);
	if (lenEmail < 6 || lenEmail > 127) return false;

	// Local part
	int lenLocal = 0;

	for (;lenLocal < lenEmail; lenLocal++) {
		if (islower(email[lenLocal]) || isdigit(email[lenLocal])) continue;
		if (lenLocal > 0 && (email[lenLocal] == '-' || email[lenLocal] == '_' || (email[lenLocal] == '.' && email[lenLocal - 1] != '.'))) continue;
		if (email[lenLocal] == '@') break;
		return false;
	}

	if (lenEmail < (lenLocal + 5) || email[lenLocal] != '@') return false;

	// Domain part
	int lastDot = 0;

	for (int i = lenLocal + 1; i < lenEmail; i++) {
		if (email[i] == '.') lastDot = i;

		if (islower(email[i]) || isdigit(email[i]) || ((email[i] == '.' || email[i] == '-') && isalnum(email[i - 1] ))) continue;
		return false;
	}

	return (lastDot > (lenLocal + 1) && lastDot < (lenEmail - 2));
}
