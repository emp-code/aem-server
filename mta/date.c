#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>

#include "date.h"

static int monthFromName(const char * const c) {
	if (strncasecmp(c, "Jan", 3) == 0) return 0;
	if (strncasecmp(c, "Feb", 3) == 0) return 1;
	if (strncasecmp(c, "Mar", 3) == 0) return 2;
	if (strncasecmp(c, "Apr", 3) == 0) return 3;
	if (strncasecmp(c, "May", 3) == 0) return 4;
	if (strncasecmp(c, "Jun", 3) == 0) return 5;
	if (strncasecmp(c, "Jul", 3) == 0) return 6;
	if (strncasecmp(c, "Aug", 3) == 0) return 7;
	if (strncasecmp(c, "Sep", 3) == 0) return 8;
	if (strncasecmp(c, "Oct", 3) == 0) return 9;
	if (strncasecmp(c, "Nov", 3) == 0) return 10;
	if (strncasecmp(c, "Dec", 3) == 0) return 11;
	return -1;
}

// Tue, 19 Oct 2012 09:59:39 -0700
// Mon, 15 Sep 2008 11:30:55
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

	const int mon = monthFromName(b + offset);
	if (mon == -1) return 0;

	offset += 3;
	while (b[offset] == ' ') offset++;

	long year = strtol(b + offset, &end, 10);
	if (year > 20 && year < 100) year += 2000;
	if (year < 2020 || end == NULL) return 0;

	b = end;
	offset = 1;
	while (b[offset] == ' ') offset++;

	const long hour = strtol(b + offset, &end, 10);
	if (hour < 0 || hour > 23) return 0;
	if (end == NULL || *end != ':') return 0;

	b = end;
	offset = 1;
	while (b[offset] == ' ') offset++;

	const long min = strtol(b + offset, &end, 10);
	if (min < 0 || min > 59) return 0;
	if (end == NULL || *end != ':') return 0;

	b = end;
	offset = 1;
	while (b[offset] == ' ') offset++;

	const long sec = strtol(b + offset, &end, 10);
	if (sec < 0 || sec > 59) return 0;
	if (end == NULL || *end != ' ') return 0;

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
