#include <ctype.h>
#include <strings.h>
#include <time.h>
#include <stdlib.h>

#include "date.h"

time_t smtp_getTime(const char *b, unsigned char * const tzp) {
	if (b == NULL || b[0] == '\0') return 0;

	size_t offset = (
	   strncasecmp(b, "Mon,", 4) == 0
	|| strncasecmp(b, "Tue,", 4) == 0
	|| strncasecmp(b, "Wed,", 4) == 0
	|| strncasecmp(b, "Thu,", 4) == 0
	|| strncasecmp(b, "Fri,", 4) == 0
	|| strncasecmp(b, "Sat,", 4) == 0
	|| strncasecmp(b, "Sun,", 4) == 0
	) ? 4 : 0;

	while (b[offset] == ' ') offset++;

	if (!isdigit(b[offset])) return 0;
	char *end = NULL;
	const long mday = strtol(b + offset, &end, 10);
	if (mday < 1 || mday > 31 || end == NULL) return 0;

	b = end;
	offset = 0;
	while (b[offset] == ' ') offset++;

	int mon = -1;
	if      (strncasecmp(b + offset, "Jan", 3) == 0) mon = 0;
	else if (strncasecmp(b + offset, "Feb", 3) == 0) mon = 1;
	else if (strncasecmp(b + offset, "Mar", 3) == 0) mon = 2;
	else if (strncasecmp(b + offset, "Apr", 3) == 0) mon = 3;
	else if (strncasecmp(b + offset, "May", 3) == 0) mon = 4;
	else if (strncasecmp(b + offset, "Jun", 3) == 0) mon = 5;
	else if (strncasecmp(b + offset, "Jul", 3) == 0) mon = 6;
	else if (strncasecmp(b + offset, "Aug", 3) == 0) mon = 7;
	else if (strncasecmp(b + offset, "Sep", 3) == 0) mon = 8;
	else if (strncasecmp(b + offset, "Oct", 3) == 0) mon = 9;
	else if (strncasecmp(b + offset, "Nov", 3) == 0) mon = 10;
	else if (strncasecmp(b + offset, "Dec", 3) == 0) mon = 11;
	if (mon == -1) return 0;

	offset += 3;
	while (b[offset] == ' ') offset++;

	int year = strtol(b + offset, &end, 10);
	if (year > 20 && year < 100) year += 2000;
	if (year < 2020) return 0;

	b = end;
	offset = 1;
	while (b[offset] == ' ') offset++;

	int hour = strtol(b + offset, &end, 10);
	if (*end != ':') return 0;
	b = end;
	offset = 1;
	while (b[offset] == ' ') offset++;

	int min = strtol(b + offset, &end, 10);
	if (*end != ':') return 0;
	b = end;
	offset = 1;
	while (b[offset] == ' ') offset++;

	int sec = strtol(b + offset, &end, 10);
	if (*end != ' ') return 0;
	b = end;
	offset = 0;
	while (b[offset] == ' ') offset++;

	long tzOff = 0;
	if ((b[offset] == '+' || b[offset] == '-') && isdigit(b[offset + 1]) && isdigit(b[offset + 2]) && isdigit(b[offset + 3]) && isdigit(b[offset + 4])) {
		tzOff += (b[offset + 1] - '0') * 60 * 600;
		tzOff += (b[offset + 2] - '0') * 60 * 60;
		tzOff += (b[offset + 3] - '0') * 600;
		tzOff += (b[offset + 4] - '0') * 60;
		if (b[offset] == '-') tzOff *= -1;
	}

	if (tzOff < -54000) tzOff = -54000; // -1500
	else if (tzOff > 54000) tzOff = 54000; // +1500

	struct tm t;
	bzero(&t, sizeof(struct tm));
	t.tm_sec = sec;
	t.tm_min = min;
	t.tm_hour = hour;
	t.tm_mday = mday;
	t.tm_mon = mon;
	t.tm_year = year - 1900; // Number of years since 1900

	*tzp = ((tzOff + 54000) / 900); // 15m
	return mktime(&t) - tzOff; // Convert to UTC+0
}
