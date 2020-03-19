#define _GNU_SOURCE // for memmem

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "Include/Base64.h"
#include "Include/QuotedPrintable.h"
#include "Include/HtmlToText.h"
#include "Include/ToUtf8.h"
#include "Include/Trim.h"

#include "processing.h"

void removeControlChars(unsigned char * const text, size_t * const len) {
	for (size_t i = 0; i < *len; i++) {
		if (text[i] == 127 || (text[i] < 32 && text[i] != '\t' && text[i] != '\n')) { // 127=DEL
			(*len)--;
			memmove(text + i, text + i + 1, *len - i);
			i--;
		}
	}
}

void tabsToSpaces(char * const text, const size_t len) {
	char *c = memchr(text, '\t', len);
	size_t skip = 0;

	while (c != NULL) {
		*c = ' ';

		skip = c - text;
		c = memchr(text + skip, '\t', len - skip);
	}
}

// Example: =?iso-8859-1?Q?=A1Hola,_se=F1or!?=
void decodeEncodedWord(char * const data, size_t * const lenData) {
	if (data == NULL || lenData == NULL || *lenData < 1) return;

	while(1) {
		const char * const headersEnd = memmem(data, *lenData, "\n\n", 2);
		if (headersEnd == NULL) break;

		const size_t searchLen = headersEnd - data;
		char * const ew = memmem(data, searchLen, "=?", 2);
		if (ew == NULL) break;

		// Remove charset part
		char * const charsetEnd = memchr(ew + 2, '?', (data + *lenData) - (ew + 2));
		if (charsetEnd == NULL) break;
		if (charsetEnd[2] != '?') break;

		const size_t csLen = charsetEnd - (ew + 2);
		char cs[csLen + 1];
		memcpy(cs, (ew + 2), csLen);
		cs[csLen] = '\0';

		const char type = charsetEnd[1];
		char *ewText = charsetEnd + 3;

		const char * const ewEnd = memmem(ewText, *lenData - (ewText - data), "?=", 2);
		if (ewEnd == NULL) break;

		size_t lenEw = ewEnd - ew;
		size_t lenEwText = ewEnd - ewText;

		if (lenEwText == 0) {
			memmove(ew, ewEnd + 2, (data + *lenData) - (ewEnd + 2));
			*lenData -= (lenEw + 2);
			continue;
		}

		while(1) {
			char * const underscore = memchr(ewText, '_', lenEwText);
			if (underscore == NULL) break;
			*underscore = ' ';
		}

		if (type == 'Q' || type == 'q') {
			decodeQuotedPrintable(ewText, &lenEwText);
		} else if (type == 'B' || type == 'b') {
			unsigned char * const dec = b64Decode((const unsigned char*)ewText, lenEwText, &lenEwText);
			if (dec == NULL) break;

			memcpy(ewText, dec, lenEwText);
			free(dec);
		} else break;

		int lenUtf8 = 0;
		char *utf8 = toUtf8(ewText, lenEwText, &lenUtf8, cs);
		if (utf8 != NULL) {
			const int lenDiff = lenEw - lenUtf8;
			if (lenDiff > 0) {
				memcpy(ew, utf8, lenUtf8);
				memmove(ew + lenUtf8, ewEnd + 2, *lenData - (ewEnd + 2 - data));
				*lenData -= (lenDiff + 2);
			} else {
				// TODO: UTF-8 version is longer
				break;
			}

			free(utf8);
		}
	}
}

void unfoldHeaders(char * const data, size_t * const lenData) {
	const char * const headersEnd = memmem(data, *lenData, "\n\n", 2);
	if (headersEnd == NULL) return;
	size_t lenHeaders = headersEnd - data;

	while(1) {
		char *lfSp = memmem(data + 2, lenHeaders, "\n ", 2);
		if (lfSp == NULL) break;

		const size_t num = (memcmp(lfSp - 2, "?=", 2) == 0) ? 2 : 1; // Remove space if previous line ended with an Encoded-Word

		memmove(lfSp, lfSp + num, (data + *lenData) - (lfSp + num));

		*lenData -= num;
		lenHeaders -= num;
		data[*lenData] = '\0';
	}
}

static char *decodeMp(const char * const msg, size_t *outLen) {
	char *out = NULL;
	*outLen = 0;

	int boundCount = 0;
	const char *b = strstr(msg, "Content-Type: multipart/");
	if (b == NULL) return NULL;

	while (1) {
		boundCount++;
		b = strstr(b + 24, "Content-Type: multipart/");
		if (b == NULL) break;
	}

	char *bound[boundCount];
	b = strstr(msg, "Content-Type: multipart/");

	for (int i = 0; i < boundCount; i++) {
		b = strcasestr(b, "boundary=");
		if (b == NULL) {boundCount = i; break;}
		b += 9;
		if (*b == '"') b++;

		const size_t len = strcspn(b, "\" \r\n");
		bound[i] = strndup(b - 2, len);
		memcpy(bound[i], "--", 2);

		b = strstr(b + 24, "Content-Type: multipart/");
		if (b == NULL) break;
	}

	const char *searchBegin = msg;
	for (int i = 0; i < boundCount;) {
		const char *begin = strstr(searchBegin, bound[i]);
		if (begin == NULL) {i++; continue;}
		begin += strlen(bound[i]);

		const char *hend = strstr(begin, "\r\n\r\n");
		const char * const hend2 = strstr(begin, "\n\n");
		size_t lenHend;
		if (hend2 != NULL && (hend == NULL || hend2 < hend)) {
			hend = hend2;
			lenHend = 2;
		} else lenHend = 4;
		if (hend == NULL) break;

		const char *cte = strcasestr(begin, "\nContent-Transfer-Encoding: ");
		if (cte != NULL && cte < hend) {
			if (strncasecmp(cte + 28, "quoted-printable", 16) == 0) cte = "Q";
			else if (strncasecmp(cte + 28, "base64", 6) == 0) cte = "B";
			else cte = "X";
		} else cte = "X";

		const char * const ct = strcasestr(begin, "\nContent-Type: ");
		if (ct == NULL || ct > hend) break;

		const char *boundEnd = strstr(hend + lenHend, bound[i]);

		if (strncasecmp(ct + 15, "text/", 5) == 0) {
			const bool isHtml = (strncasecmp(ct + 20, "html", 4) == 0);

			hend += lenHend;
			size_t lenNew = boundEnd - hend;

			char *charset = NULL;
			const char *cs = strstr(ct + 15, "charset=");
			if (cs == NULL) cs = strstr(ct + 15, "harset =");
			if (cs != NULL && cs < hend) {
				cs += 8;
				if (*cs == ' ') cs++;
				if (*cs == '"') cs++;
				const size_t lenCs = strcspn(cs, "\n \"'");
				charset = strndup(cs, lenCs);
			}

			char *new = NULL;

			if (*cte == 'Q') {
				new = strndup(hend, lenNew);
				if (new == NULL) {free(charset); break;}
				decodeQuotedPrintable(new, &lenNew);
			} else if (*cte == 'B') {
				new = (char*)b64Decode((unsigned char*)hend, lenNew, &lenNew);
				if (new == NULL) {free(charset); break;}
			} else {
				new = strndup(hend, lenNew);
			}

			// TODO: Support detecting charset if missing?
			if (charset != NULL && strncmp(charset, "utf8", 4) != 0 && strncmp(charset, "utf-8", 5) != 0 && strncmp(charset, "ascii", 5) != 0 && strncmp(charset, "us-ascii", 8) != 0) {
				int lenUtf8;
				char * const utf8 = toUtf8(new, lenNew, &lenUtf8, charset);
				if (utf8 != NULL) {
					free(new);
					new = utf8;
					lenNew = (size_t)lenUtf8;
				}
			}

			if (charset != NULL) free(charset);

			convertNbsp(new, &lenNew);
			tabsToSpaces(new, lenNew);
			removeControlChars((unsigned char*)new, &lenNew);

			if (isHtml) htmlToText(new, &lenNew);

			char * const out2 = realloc(out, *outLen + lenNew);
			if (out2 == NULL) break;

			out = out2;
			memcpy(out + *outLen, new, lenNew);
			*outLen += lenNew;

			free(new);
		}

		searchBegin = boundEnd;
	}

	for (int i = 0; i < boundCount; i++) free(bound[i]);

	return out;
}

void decodeMessage(char ** const msg, size_t * const lenMsg) {
	char *headersEnd = memmem(*msg,  *lenMsg, "\n\n", 2);
	if (headersEnd == NULL) return;
	headersEnd += 2;

	const char *ct = strcasestr(*msg, "\nContent-Type: ");
	if (ct == NULL) return;
	ct += 15;

	if (strncasecmp(ct, "multipart/", 10) == 0) {
		size_t lenNew;
		char * const new = decodeMp(*msg, &lenNew);

		if (new != NULL) {
			const size_t lenHeaders = headersEnd - *msg;

			const size_t lenFull = lenHeaders + lenNew;
			char * const full = malloc(lenFull);
			if (full == NULL) {free(new); return;}

			memcpy(full, *msg, lenHeaders);
			memcpy(full + lenHeaders, new, lenNew);
			free(new);

			*lenMsg = lenFull;
			free(*msg);
			*msg = full;
		}
	} else {
		char *charset = NULL;
		const char *cs = strstr(ct, "charset=");
		if (cs == NULL) cs = strstr(ct, "harset =");
		if (cs != NULL && cs < headersEnd) {
			cs += 8;
			if (*cs == ' ') cs++;
			if (*cs == '"') cs++;
			size_t lenCs = strcspn(cs, "\n \"'");
			charset = strndup(cs, lenCs);
		}

		const char *cte = strcasestr(*msg, "\nContent-Transfer-Encoding: quoted-printable");
		if (cte != NULL && cte < headersEnd) {
			size_t len = (*lenMsg) - (headersEnd - *msg);
			const size_t lenOld = len;
			decodeQuotedPrintable(headersEnd, &len);
			const size_t lenDiff = lenOld - len;
			*lenMsg -= lenDiff;
		} else  {
			cte = strcasestr(*msg, "\nContent-Transfer-Encoding: base64");
			if (cte != NULL && cte < headersEnd) {
				const size_t lenOld = *lenMsg - (headersEnd - *msg);
				size_t len;
				unsigned char * const e = b64Decode((unsigned char*)headersEnd, lenOld, &len);
				if (e != NULL) {
					memcpy(headersEnd, e, len);
					const size_t lenDiff = lenOld - len;
					*lenMsg -= lenDiff;
					free(e);
				}
			}
		}

		// TODO: Support detecting charset if missing?
		if (charset != NULL && strncmp(charset, "utf8", 4) != 0 && strncmp(charset, "utf-8", 5) != 0 && strncmp(charset, "ascii", 5) != 0 && strncmp(charset, "us-ascii", 8) != 0) {
			int lenUtf8;
			const int lenOld = (*msg + *lenMsg) - headersEnd;
			char * const utf8 = toUtf8(headersEnd, lenOld, &lenUtf8, charset);
			if (utf8 != NULL) {
				if (lenOld > lenUtf8) {
					memcpy(headersEnd, utf8, lenUtf8);
					*lenMsg -= (lenOld - lenUtf8);
				} else {
					const size_t lenHeaders = headersEnd - *msg;
					char * const new = malloc(lenHeaders + lenUtf8);
					if (new != NULL) {
						memcpy(new, *msg, lenHeaders);
						free(*msg);
						memcpy(new + lenHeaders, utf8, lenUtf8);
						free(utf8);
						*msg = new;
					}
				}

				headersEnd = memmem(*msg,  *lenMsg, "\n\n", 2);
			}
		}

		if (charset != NULL) free(charset);

		tabsToSpaces(*msg, *lenMsg);
		removeControlChars((unsigned char*)(*msg), lenMsg);
		convertNbsp(*msg, lenMsg);

		ct = strcasestr(*msg, "\nContent-Type: ");
		if (strncasecmp(ct + 15, "text/html", 9) == 0) {
			size_t lenHe = (*msg + *lenMsg) - headersEnd;
			const size_t lenOld = lenHe;
			htmlToText(headersEnd, &lenHe);
			*lenMsg -= (lenOld - lenHe);
		}
	}
}
