#include <string.h>
#include <ctype.h> // for isupper/tolower
#include <sys/types.h> // for ssize_t

#include "HtmlRefs.h"
#include "Trim.h"

#include "HtmlToText.h"

#define AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK 0x01
#define AEM_HTMLTOTEXT_PLACEHOLDER_SINGLEQUOTE 0x02
#define AEM_HTMLTOTEXT_PLACEHOLDER_GT 0x03
#define AEM_HTMLTOTEXT_PLACEHOLDER_LT 0x04

static void filterText(char * const text, size_t * const lenText, const char * const bad, const size_t lenBad, const char good) {
	while(1) {
		char * const c = memmem(text, *lenText, bad, lenBad);
		if (c == NULL) break;
		*c = good;

		memmove(c + 1, c + lenBad, (text + *lenText) - (c + lenBad));
		*lenText -= (lenBad - 1);
	}
}

static void filterHr(char * const text, const size_t len) {
	while(1) {
		char * const c = memmem(text, len, "<hr>", 4);
		if (c == NULL) break;
		c[0] = AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK;
		c[1] = '-';
		c[2] = '-';
		c[3] = AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK;
	}

	while(1) {
		char * const c = memmem(text, len, "<hr/>", 5);
		if (c == NULL) break;
		c[0] = AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK;
		c[1] = '-';
		c[2] = '-';
		c[3] = '-';
		c[4] = AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK;
	}

	while(1) {
		char * const c = memmem(text, len, "<hr />", 6);
		if (c == NULL) break;
		c[0] = AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK;
		c[1] = '-';
		c[2] = '-';
		c[3] = AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK;
		c[4] = '<'; // '<>' remains, and gets removed
	}
}

static void placeLinebreak(char * const text, const size_t len, const char * const search) {
	while(1) {
		char * const c = memmem(text, len, search, strlen(search));
		if (c == NULL) return;
		c[0] = AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK;
		c[1] = '<';
	}
}

static void convertChar(char * const text, const size_t lenText, const char from, const char to) {
	while(1) {
		char * const c = memchr(text, from, lenText);
		if (c == NULL) return;
		*c = to;
	}
}

static void removeHtmlComments(char * const text, size_t * const len) {
	while(1) {
		char * const c = memmem(text, *len, "<!--", 4);
		if (c == NULL) break;

		const char * const end = memmem(c + 4, (text + *len) - (c + 4), "-->", 3);
		if (end == NULL) return;

		memmove(c, end + 3, (text + *len) - (end + 3));

		*len -= (end + 3 - c);
	}
}

static void lfToSpace(char * const text, const size_t len) {
	char *c = memchr(text, '\n', len);

	while (c != NULL) {
		*c = ' ';

		const size_t skip = c - text;
		c = memchr(text + skip, '\n', len - skip);
	}
}

static void bracketsInQuotes_single(const char * const br1, char ** const br2) {
	const char *qt1 = strchr(br1, '\'');
	while (qt1 != NULL && qt1 < *br2) {
		const char * const qt2 = strchr(qt1 + 1, '\'');
		if (qt2 == NULL) break;

		while (*br2 < qt2) {
			*br2 = strchr(qt2 + 1, '>');
			if (*br2 == NULL) return;
		}

		char *c = memchr(qt1 + 1, '<', qt2 - (qt1 + 1));
		while (c != NULL) {
			*c = AEM_HTMLTOTEXT_PLACEHOLDER_LT;
			c = memchr(qt1 + 1, '<', qt2 - (qt1 + 1));
		}

		c = memchr(qt1 + 1, '>', qt2 - (qt1 + 1));
		while (c != NULL) {
			*c = AEM_HTMLTOTEXT_PLACEHOLDER_GT;
			c = memchr(qt1 + 1, '>', qt2 - (qt1 + 1));
		}

		// br2 is now beyond the quote character, look for next quote
		qt1 = strchr(qt2 + 1, '\'');
		if (qt1 == NULL || qt1 > *br2) break;
	}
}

static void bracketsInQuotes_double(const char * const br1, char ** const br2) {
	const char *qt1 = strchr(br1, '"');
	while (qt1 != NULL && qt1 < *br2) {
		const char * const qt2 = strchr(qt1 + 1, '"');
		if (qt2 == NULL) break;
		while (*br2 < qt2) {
			*br2 = strchr(qt2 + 1, '>');
			if (*br2 == NULL) return;
		}

		char *c = memchr(qt1 + 1, '\'', qt2 - (qt1 + 1));
		while (c != NULL) {
			*c = AEM_HTMLTOTEXT_PLACEHOLDER_SINGLEQUOTE;
			c = memchr(qt1 + 1, '\'', qt2 - (qt1 + 1));
		}

		c = memchr(qt1 + 1, '<', qt2 - (qt1 + 1));
		while (c != NULL) {
			*c = AEM_HTMLTOTEXT_PLACEHOLDER_LT;
			c = memchr(qt1 + 1, '<', qt2 - (qt1 + 1));
		}

		c = memchr(qt1 + 1, '>', qt2 - (qt1 + 1));
		while (c != NULL) {
			*c = AEM_HTMLTOTEXT_PLACEHOLDER_GT;
			c = memchr(qt1 + 1, '>', qt2 - (qt1 + 1));
		}

		// br2 is now beyond the quote character, look for next quote
		qt1 = strchr(qt2 + 1, '"');
		if (qt1 == NULL || qt1 > *br2) break;
	}
}

// 1. Look for double quotes
// 2. Locate single quotes within double quotes, change them into a placeholder character
// 3. Locate angle brackets, change them into placeholders
// 4. Look for single quotes
// 5. Repeat step 3
// 6. Convert single quotes to double quotes (src='abc' -> src="abc")
static void bracketsInQuotes(char *text) {
	char *br1 = strchr(text, '<');

	while (br1 != NULL) {
		char *br2 = strchr(br1 + 1, '>');
		if (br2 == NULL) break;

		bracketsInQuotes_double(br1, &br2);
		bracketsInQuotes_single(br1, &br2);
		bracketsInQuotes_double(br1, &br2);

		if (br2 == NULL) break;
		convertChar(br1, br2 - br1, '\'', '"');

		br1 = strchr(br2 + 1, '<');
	}
}

// Needs bracketsInQuotes() and lfToSpace()
// Replaces <a href="example"> with example
static void processLinks(char *text, size_t *len) {
	char *br1 = memmem(text, *len, "<a ", 3);
	while (br1 != NULL) {
		char *br2 = memchr(br1, '>', (text + *len) - br1);
		if (br2 == NULL) break;

		const char *url = memmem(br1, br2 - br1, "href=", 5);

		if (url != NULL) {
			url += 5;

			const size_t lenOrig = br2 - br1;

			if (*url == '"') {
				url++;
				const char * const term = memchr(url, '"', br2 - url);

				if (term != NULL) {
					const size_t lenUrl = term - url;
					memmove(br1, url, lenUrl);
					*br2 = ' ';
					memmove(br1 + lenUrl, br2, (text + *len) - br2);
					*len -= (lenOrig - lenUrl);
					br2 = br1 + lenUrl;
				} else {br1 = br2 + 1;}
			} else {
				const char * const term = strpbrk(url, " >");

				if (term != NULL && term < br2) {
					const size_t lenUrl = term - url;
					memmove(br1, url, lenUrl);
					*br2 = ' ';
					memmove(br1 + lenUrl, br2, (text + *len) - br2);
					*len -= (lenOrig - lenUrl);
					br2 = br1 + lenUrl;
				} else br1 = br2 + 1;
			}
		} else br1 = br2 + 1;

		br1 = memmem(br1, (text + *len) - br1, "<a ", 3);
	}
}

// Needs bracketsInQuotes() and lfToSpace()
// Replaces <img src="example"> with example
// TODO: Preserve title/alt/size
static void processImages(char * const text, size_t * const len) {
	char *br1 = memmem(text, *len, "<img ", 5);
	while (br1 != NULL) {
		char *br2 = memchr(br1, '>', (text + *len) - br1);
		if (br2 == NULL) break;

		const char *url = memmem(br1, br2 - br1, "src=", 4);

		if (url != NULL) {
			url += 4;

			const size_t lenOrig = br2 - br1;

			if (*url == '"') {
				url++;
				const char * const term = memchr(url, '"', br2 - url);

				if (term != NULL) {
					const size_t lenUrl = term - url;
					memmove(br1, url, lenUrl);
					*br2 = ' ';
					memmove(br1 + lenUrl, br2, (text + *len) - br2);
					*len -= (lenOrig - lenUrl);
					br2 = br1 + lenUrl;
				} else {br1 = br2 + 1;}
			} else {
				const char * const term = strpbrk(url, " >");

				if (term != NULL && term < br2) {
					const size_t lenUrl = term - url;
					memmove(br1, url, lenUrl);
					*br2 = ' ';
					memmove(br1 + lenUrl, br2, (text + *len) - br2);
					*len -= (lenOrig - lenUrl);
					br2 = br1 + lenUrl;
				} else br1 = br2 + 1;
			}
		} else br1 = br2 + 1;

		br1 = memmem(br1, (text + *len) - br1, "<img ", 5);
	}
}

static void removeHtml(char * const text, size_t * const len) {
	char *br1 = memchr(text, '<', *len);

	while (br1 != NULL) {
		const char *br2 = memchr(br1 + 1, '>', (text + *len) - (br1 + 1));
		if (br2 == NULL) return;
		br2++;

		memmove(br1, br2, (text + *len) - br2);
		*len -= (br2 - br1);
		text[*len] = '\0';

		br1 = memchr(text, '<', *len);
	}
}

void removeStyle(char * const text, size_t * const len) {
	char * const begin = memmem(text, *len, "<style", 6);
	if (begin == NULL) return;

	const char * const end = memmem(begin + 6, *len - ((begin + 6) - text), "</style>", 8);
	if (end == NULL) return;

	const size_t diff = (end + 8) - begin;
	memmove(begin, end + 8, (text + *len) - (end + 8));
	*len -= diff;
}

void lowercaseHtmlTags(char * const text, const size_t len) {
	char *c = memchr(text, '<', len);

	while (c != NULL) {
		const char * const d = memchr(c, '>', (text + len) - c);
		if (d == NULL) break;

		for (int i = 0; i < d - c; i++) {
			if (isupper(c[i]))
				c[i] = tolower(c[i]);
			else if (c[i] == ' ' || c[i] == '\n')
				break;
		}

		const ssize_t bytes = (text + len) - (d + 1);
		if (bytes < 1) break;
		c = memchr(d + 1, '<', bytes);
	}
}

void htmlToText(char * const text, size_t * const len) {
	lfToSpace(text, *len);
	removeHtmlComments(text, len);

	// Remove content before body tag
	const char * const body = memmem(text, *len, "<body", 5);
	if (body != NULL) {
		const size_t rem = body - text;
		*len -= rem;
		memmove(text, body, *len);
	}

	text[*len] = '\0';
	bracketsInQuotes(text);
	lowercaseHtmlTags(text, *len);

	filterHr(text, *len);
	filterText(text, len, "<br>", 4, AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK);
	filterText(text, len, "<br/>", 5, AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK);
	filterText(text, len, "<br />", 6, AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK);
	text[*len] = '\0';

	placeLinebreak(text, *len, "<table");
	placeLinebreak(text, *len, "</table");
	placeLinebreak(text, *len, "<tbody");
	placeLinebreak(text, *len, "</tbody");
	placeLinebreak(text, *len, "<thead");
	placeLinebreak(text, *len, "</thead");
	placeLinebreak(text, *len, "<div");
	placeLinebreak(text, *len, "</div");
	placeLinebreak(text, *len, "<p ");
	placeLinebreak(text, *len, "<p>");
	placeLinebreak(text, *len, "</p>");
	placeLinebreak(text, *len, "<h1");
	placeLinebreak(text, *len, "<h2");
	placeLinebreak(text, *len, "<h3");
	placeLinebreak(text, *len, "<h4");
	placeLinebreak(text, *len, "<h5");
	placeLinebreak(text, *len, "<h6");
	placeLinebreak(text, *len, "</h1");
	placeLinebreak(text, *len, "</h2");
	placeLinebreak(text, *len, "</h3");
	placeLinebreak(text, *len, "</h4");
	placeLinebreak(text, *len, "</h5");
	placeLinebreak(text, *len, "</h6");
	placeLinebreak(text, *len, "<td");
	placeLinebreak(text, *len, "</td");
	placeLinebreak(text, *len, "<tr");
	placeLinebreak(text, *len, "</tr");
	placeLinebreak(text, *len, "<li");
	placeLinebreak(text, *len, "</li");
	placeLinebreak(text, *len, "<ul");
	placeLinebreak(text, *len, "</ul");

	processLinks(text, len);
	processImages(text, len);
	removeStyle(text, len);
	removeHtml(text, len);
	decodeHtmlRefs((unsigned char*)text, len);

	convertChar(text, *len, AEM_HTMLTOTEXT_PLACEHOLDER_LINEBREAK, '\n');
	convertChar(text, *len, AEM_HTMLTOTEXT_PLACEHOLDER_SINGLEQUOTE, '\'');
	convertChar(text, *len, AEM_HTMLTOTEXT_PLACEHOLDER_GT, '>');
	convertChar(text, *len, AEM_HTMLTOTEXT_PLACEHOLDER_LT, '<');
}
