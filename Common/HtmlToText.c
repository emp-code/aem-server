#include <string.h>
#include <ctype.h> // for isupper/tolower
#include <sys/types.h> // for ssize_t

#include "../Global.h"
#include "HtmlRefs.h"
#include "Trim.h"

#include "HtmlToText.h"

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
		c[0] = AEM_HTML_PLACEHOLDER_LINEBREAK;
		c[1] = '-';
		c[2] = '-';
		c[3] = AEM_HTML_PLACEHOLDER_LINEBREAK;
	}

	while(1) {
		char * const c = memmem(text, len, "<hr/>", 5);
		if (c == NULL) break;
		c[0] = AEM_HTML_PLACEHOLDER_LINEBREAK;
		c[1] = '-';
		c[2] = '-';
		c[3] = '-';
		c[4] = AEM_HTML_PLACEHOLDER_LINEBREAK;
	}

	while(1) {
		char * const c = memmem(text, len, "<hr />", 6);
		if (c == NULL) break;
		c[0] = AEM_HTML_PLACEHOLDER_LINEBREAK;
		c[1] = '-';
		c[2] = '-';
		c[3] = AEM_HTML_PLACEHOLDER_LINEBREAK;
		c[4] = '<'; // '<>' remains, and gets removed
	}
}

static void placeLinebreak(char * const text, const size_t len, const char * const search) {
	while(1) {
		char * const c = memmem(text, len, search, strlen(search));
		if (c == NULL) return;
		c[0] = AEM_HTML_PLACEHOLDER_LINEBREAK;
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

		while(1) {
			char * const c = memchr(qt1 + 1, '<', qt2 - (qt1 + 1));
			if (c == NULL) break;
			*c = AEM_HTML_PLACEHOLDER_LT;
		}

		while(1) {
			char * const c = memchr(qt1 + 1, '>', qt2 - (qt1 + 1));
			if (c == NULL) break;
			*c = AEM_HTML_PLACEHOLDER_GT;
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

		while(1) {
			char * const c = memchr(qt1 + 1, '\'', qt2 - (qt1 + 1));
			if (c == NULL) break;
			*c = AEM_HTML_PLACEHOLDER_SINGLEQUOTE;
		}

		while(1) {
			char * const c = memchr(qt1 + 1, '<', qt2 - (qt1 + 1));
			if (c == NULL) break;
			*c = AEM_HTML_PLACEHOLDER_LT;
		}

		while(1) {
			char * const c = memchr(qt1 + 1, '>', qt2 - (qt1 + 1));
			if (c == NULL) break;
			*c = AEM_HTML_PLACEHOLDER_GT;
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

static const unsigned char *pmin(const unsigned char * const a, const unsigned char * const b) {
	return (a == NULL) ? b : ((b == NULL) ? a : ((a <= b) ? a : b));
}

static int replaceLink(unsigned char * const pos1, unsigned char * const pos2, const unsigned char linkCharBase, const unsigned char * url, const unsigned char * const sourceEnd, size_t * const lenSource) {
	if (sourceEnd - url < 3) return -1;
	if (*url == ' ') url++;

	const bool isQuot = (*url == '"');
	if (isQuot) url++;
	if (*url == ' ') url++;

	const unsigned char * const term = isQuot? memchr(url, '"', pos2 - url) : pmin(memchr(url, ' ', pos2 - url), pos2);
	if (term == NULL || !(isQuot || term <= pos2) || *url == '#') return -1;
	size_t lenUrl = term - url;

	unsigned char linkChar = linkCharBase + 1; // Secure by default
	if (lenUrl >= 2 && memcmp(url, "//", 2) == 0) {
		url += 2;
		lenUrl -= 2;
	} else if (lenUrl >= 8 && memcmp(url, "https://", 8) == 0) {
		url += 8;
		lenUrl -= 8;
	} else if (lenUrl >= 7 && memcmp(url, "http://", 7) == 0) {
		linkChar--;
		url += 7;
		lenUrl -= 7;
	} else if (lenUrl >= 6 && memcmp(url, "ftp://", 6) == 0) {
		url += 6;
		lenUrl -= 6;
	} else if (lenUrl >= 8 && memcmp(url, "mailto://", 9) == 0) {
		url += 9;
		lenUrl -= 9;
		linkChar = AEM_CET_CHAR_MLT;
	} else return -1;

	// Replace the content
	*pos1 = linkChar;
	memmove(pos1 + 1, url, lenUrl); // TODO: Lowercase domain (until slash)
	*pos2 = linkChar;

	// Move rest of the content to its new beginning
	memmove(pos1 + 1 + lenUrl, pos2, sourceEnd - pos2);
	*lenSource -= ((pos2 - pos1) - lenUrl - 1);
	return 0;
}

// tag: include bracket and space, like "<a "; param: include equals-sign at end
static void extractLink(unsigned char *text, size_t *len, const char * const tag, const size_t lenTag, const char * const param, const size_t lenParam, const unsigned char linkChar) {
	unsigned char *br1 = memmem(text, *len, tag, lenTag);
	while (br1 != NULL) {
		unsigned char *br2 = memchr(br1 + 1, '>', (text + *len) - (br1 + 1));
		if (br2 == NULL) break;

		const unsigned char *url = memmem(br1 + 1, br2 - (br1 + 1), param, lenParam);
		if (url == NULL || replaceLink(br1, br2, linkChar, url + lenParam, text + *len, len) != 0) {
			br2++;
			const size_t lenRem = br2 - br1;
			memmove(br1, br2, (text + *len) - br2);
			*len -= lenRem;
		}

		br1 = memmem(br1, (text + *len) - br1, tag, lenTag);
	}
}

// Needs bracketsInQuotes() and lfToSpace()
static void processLinks(unsigned char *text, size_t *len) {
	extractLink(text, len, "<a ",      3, "href=", 5, AEM_CET_CHAR_LNK);
	extractLink(text, len, "<frame ",  7, "src=",  4, AEM_CET_CHAR_LNK);
	extractLink(text, len, "<iframe ", 8, "src=",  4, AEM_CET_CHAR_LNK);

	extractLink(text, len, "<audio ",  7, "src=",  4, AEM_CET_CHAR_FIL);
	extractLink(text, len, "<embed ",  7, "src=",  4, AEM_CET_CHAR_FIL);
	extractLink(text, len, "<img ",    5, "src=",  4, AEM_CET_CHAR_FIL);
	extractLink(text, len, "<object ", 8, "data=", 5, AEM_CET_CHAR_FIL);
	extractLink(text, len, "<source ", 8, "src=",  4, AEM_CET_CHAR_FIL);
	extractLink(text, len, "<track ",  7, "src=",  4, AEM_CET_CHAR_FIL);
	extractLink(text, len, "<video ",  7, "src=",  4, AEM_CET_CHAR_FIL);
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

static void removeStyle(char * const text, size_t * const len) {
	char * const begin = memmem(text, *len, "<style", 6);
	if (begin == NULL) return;

	const char * const end = memmem(begin + 6, *len - ((begin + 6) - text), "</style>", 8);
	if (end == NULL) return;

	const size_t diff = (end + 8) - begin;
	memmove(begin, end + 8, (text + *len) - (end + 8));
	*len -= diff;
}

static void lowercaseHtmlTags(char * const text, const size_t len) {
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
	removeControlChars((unsigned char*)text, len);
	lfToSpace(text, *len);
	removeHtmlComments(text, len);
	text[*len] = '\0';
	decodeHtmlRefs((unsigned char*)text, len);

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
	filterText(text, len, "<br>", 4, AEM_HTML_PLACEHOLDER_LINEBREAK);
	filterText(text, len, "<br/>", 5, AEM_HTML_PLACEHOLDER_LINEBREAK);
	filterText(text, len, "<br />", 6, AEM_HTML_PLACEHOLDER_LINEBREAK);

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

	processLinks((unsigned char*)text, len);
	removeStyle(text, len);
	removeHtml(text, len);

	convertChar(text, *len, AEM_HTML_PLACEHOLDER_LINEBREAK, '\n');
	convertChar(text, *len, AEM_HTML_PLACEHOLDER_SINGLEQUOTE, '\'');
	convertChar(text, *len, AEM_HTML_PLACEHOLDER_DOUBLEQUOTE, '"');
	convertChar(text, *len, AEM_HTML_PLACEHOLDER_GT, '>');
	convertChar(text, *len, AEM_HTML_PLACEHOLDER_LT, '<');

	text[*len] = '\0';
}
