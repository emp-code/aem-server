#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>

#include <sodium.h>

#include "../Common/QuotedPrintable.h"
#include "../Common/HtmlToText.h"
#include "../Common/ToUtf8.h"
#include "../Common/Trim.h"

#include "processing.h"

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

		const size_t lenCs = charsetEnd - (ew + 2);
		char cs[lenCs + 1];
		memcpy(cs, (ew + 2), lenCs);
		cs[lenCs] = '\0';

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
			unsigned char * const dec = malloc(lenEwText);
			size_t lenDec;
			if (dec == NULL || sodium_base642bin(dec, lenEwText, ewText, lenEwText, " \t\v\f\r\n", &lenDec, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {free(dec); break;}

			memcpy(ewText, dec, lenDec);
			lenEwText = lenDec;
			free(dec);
		} else break;

		int lenUtf8 = 0;
		char *utf8 = toUtf8(ewText, lenEwText, &lenUtf8, cs);
		if (utf8 == NULL) break;

		const size_t lenDiff = lenEw - lenUtf8;
		if (lenDiff > 0) {
			memcpy(ew, utf8, lenUtf8);
			memmove(ew + lenUtf8, ewEnd + 2, (data + *lenData) - (ewEnd + 2));
			*lenData -= (lenDiff + 2);
		} else {
			// TODO: UTF-8 version is longer or same
			break;
		}

		free(utf8);
	}
}

int prepareHeaders(char * const data, size_t * const lenData) {
	const char *headersEnd = memmem(data, *lenData, "\r\n\r\n", 4);
	const char * const headersEnd2 = memmem(data, *lenData, "\n\n", 2);
	if (headersEnd2 != NULL && headersEnd2 < headersEnd) headersEnd = headersEnd2 + 2; else headersEnd += 4;
	if (headersEnd == NULL) return -1;

	size_t lenHeaders = headersEnd - data;
	const size_t lenHeaders_original = lenHeaders;
	removeControlChars((unsigned char*)data, &lenHeaders);

	memmove(data + lenHeaders, data + lenHeaders_original, (data + *lenData) - (data + lenHeaders_original));
	*lenData -= (lenHeaders_original - lenHeaders);
	return 0;
}

void unfoldHeaders(char * const data, size_t * const lenData) {
	const char * const headersEnd = memmem(data, *lenData, "\n\n", 2);
	if (headersEnd == NULL) return;
	size_t lenHeaders = headersEnd - data;

	while(1) {
		char * const lfSp = memmem(data + 2, lenHeaders, "\n ", 2);
		if (lfSp == NULL) break;

		const size_t num = (memcmp(lfSp - 2, "?=", 2) == 0) ? 2 : 1; // Remove space if previous line ended with an Encoded-Word

		memmove(lfSp, lfSp + num, (data + *lenData) - (lfSp + num));

		*lenData -= num;
		lenHeaders -= num;
		data[*lenData] = '\0';
	}
}

static char *decodeMp(const char * const msg, size_t *outLen, struct emailInfo * const email, char * const firstBound) {
	char *out = NULL;
	*outLen = 0;

	int boundCount = 1;
	char *bound[50];
	bound[0] = firstBound;

	const char *searchBegin = msg;
	for (int i = 0; i < ((boundCount > 50) ? 50 : boundCount);) {
		const char *begin = strstr(searchBegin, bound[i]);
		if (begin == NULL) break;

		begin += strlen(bound[i]);

		if (begin[0] == '-' && begin[1] == '-' && (begin[2] == '\r' || begin[2] == '\n')) {
			searchBegin = msg;
			i++;
			continue;
		}

		const char *hend = strstr(begin, "\r\n\r\n");
		const char * const hend2 = strstr(begin, "\n\n");
		size_t lenHend;
		if (hend2 != NULL && (hend == NULL || hend2 < hend)) {
			hend = hend2;
			lenHend = 2;
		} else lenHend = 4;
		if (hend == NULL) break;

		const char *cte = strcasestr(begin, "\nContent-Transfer-Encoding:");
		if (cte != NULL && cte < hend) {
			while(1) {if (isspace(cte[27])) cte++; else break;}
			if (cte[27] == '\0') break;

			if (strncasecmp(cte + 27, "quoted-printable", 16) == 0) cte = "Q";
			else if (strncasecmp(cte + 27, "base64", 6) == 0) cte = "B";
			else cte = "X";
		} else cte = "X";

		const char *ct = strcasestr(begin, "\nContent-Type:");
		if (ct > hend) {
			ct = NULL;
		} else if (ct != NULL) {
			while(1) {if (isspace(ct[14])) ct++; else break;}
			if (ct[14] == '\0') break;
		}

		const char *fn = strcasestr(begin, "name=");
		if (fn > hend) fn = NULL;

		const char *boundEnd = strstr(hend + lenHend, bound[i]);
		if (boundEnd == NULL) break;

		hend += lenHend;
		size_t lenNew = boundEnd - hend;

		const bool isText = (ct != NULL) && (strncasecmp(ct + 14, "text/", 5) == 0);
		const bool isHtml = (ct != NULL) && (strncasecmp(ct + 14, "text/html", 9) == 0);
		const bool ignore = (ct != NULL) && (strncasecmp(ct + 14, "multipart", 9) == 0);

		if (ignore) {
			char *newBegin = strcasestr(ct + 14, "boundary=");
			if (newBegin != NULL && newBegin < hend) {
				newBegin += 9;
				const char *newEnd;

				if (newBegin[0] == '"') {
					newBegin++;
					newEnd = strchr(newBegin, '"');
				} else if (newBegin[0] == '\'') {
					newBegin++;
					newEnd = strchr(newBegin, '\'');
				} else {
					newEnd = strpbrk(newBegin, "; \t\v\f\r\n");
				}

				if (newEnd != NULL) {
					bound[boundCount] = malloc(4 + (newEnd - newBegin));
					memcpy(bound[boundCount] + 3, newBegin, newEnd - newBegin);
					bound[boundCount][0] = '\n';
					bound[boundCount][1] = '-';
					bound[boundCount][2] = '-';
					bound[boundCount][3 + (newEnd - newBegin)] = '\0';
					boundCount++;
				}
			}
		}

		char *charset = NULL;
		size_t lenCs = 0;
		if (isText) {
			const char *cs = strcasestr(ct + 14, "charset=");
			if (cs == NULL) cs = strcasestr(ct + 14, "harset =");
			if (cs != NULL && cs < hend) {
				cs += 8;
				if (*cs == ' ') cs++;
				if (*cs == '"') cs++;
				lenCs = strcspn(cs, "\n \"'");
				charset = strndup(cs, lenCs);
				if (charset == NULL) break;
			}
		}

		char *new = NULL;

		if (*cte == 'Q') {
			new = strndup(hend, lenNew);
			if (new == NULL) {if (charset != NULL) {free(charset);} break;}
			decodeQuotedPrintable(new, &lenNew);
		} else if (*cte == 'B') {
			new = malloc(lenNew);
			size_t lenNew2;
			if (new == NULL || sodium_base642bin((unsigned char*)new, lenNew, hend, lenNew, " \t\v\f\r\n", &lenNew2, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {if (charset != NULL) {free(charset);} break;}
			new[lenNew2] = '\0';
			lenNew = lenNew2;
		} else {
			new = strndup(hend, lenNew);
			if (new == NULL) {if (charset != NULL) {free(charset);} break;}
		}

		// TODO: Support detecting charset if missing?
		if (charset != NULL && !isUtf8(charset, lenCs)) {
			char cs8[lenCs + 1];
			memcpy(cs8, charset, lenCs);
			cs8[lenCs] = '\0';

			int lenUtf8;
			char * const utf8 = toUtf8(new, lenNew, &lenUtf8, cs8);
			if (utf8 != NULL) {
				free(new);
				new = utf8;
				lenNew = (size_t)lenUtf8;
			}
		}
		if (charset != NULL) free(charset);

		if (isText) {
			convertNbsp(new, &lenNew);
			removeControlChars((unsigned char*)new, &lenNew);
			if (isHtml) htmlToText(new, &lenNew);

			char * const out2 = realloc(out, *outLen + lenNew);
			if (out2 == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}
			out = out2;

			memcpy(out + *outLen, new, lenNew);
			*outLen += lenNew;
		} else if (!ignore && email->attachCount < AEM_MAXNUM_ATTACHMENTS) {
			size_t lenFn = 0;
			if (fn != NULL) {
				fn += 5; // name=

				if (*fn == '"') {
					fn++;
					char *fnEnd = memchr(fn, '"', hend - fn);
					if (fnEnd != NULL) lenFn = fnEnd - fn;
				} else if (*fn == '\'') {
					fn++;
					char *fnEnd = memchr(fn, '\'', hend - fn);
					if (fnEnd != NULL) lenFn = fnEnd - fn;
				} else {
					for (const char *fnEnd = fn; fnEnd < hend; fnEnd++) {
						if (isspace(*fnEnd) || *fnEnd == ';') {
							lenFn = fnEnd - fn;
							break;
						}
					}
				}
			} else {
				fn = "AEM-NoName";
				lenFn = 10;
			}

			if (lenFn > 256) lenFn = 256;

			if (lenFn > 0 && (lenFn + lenNew) <= 1048576) { // 1 MiB, TODO more exact
				email->attachment[email->attachCount] = malloc(17 + lenFn + lenNew);

				if (email->attachment[email->attachCount] != NULL) {
					email->attachment[email->attachCount][0] = (lenFn - 1);
					// 16 bytes reserved for MsgId
					memcpy(email->attachment[email->attachCount] + 17, fn, lenFn);
					memcpy(email->attachment[email->attachCount] + 17 + lenFn, new, lenNew);

					email->attachSize[email->attachCount] = 17 + lenFn + lenNew;
					(email->attachCount)++;
				} else syslog(LOG_ERR, "Failed allocation");
			}
		}

		free(new);
		searchBegin = boundEnd;
	}

	for (int i = 0; i < boundCount; i++) free(bound[i]);

	return out;
}

static void removeHeaderSpace(char * msg, size_t * const lenMsg) {
	char *c = memchr(msg, ':', *lenMsg - 1);
	while (c != NULL) {
		if (c[1] == ' ') {
			memmove(c + 1, c + 2, (msg + *lenMsg) - (c + 2));
			(*lenMsg)--;
		}

		c = memchr(c + 1, '\n', (msg + *lenMsg) - (c + 1) - 1);
		if (c == NULL) break;
		c = memchr(c + 1, ':', (msg + *lenMsg) - (c + 1) - 1);
	}
}

void decodeMessage(char ** const msg, size_t * const lenMsg, struct emailInfo * const email) {
	char *headersEnd = memmem(*msg,  *lenMsg, "\n\n", 2);
	if (headersEnd == NULL) return;
	headersEnd += 2;

	removeHeaderSpace(*msg, lenMsg);

	headersEnd = memmem(*msg,  *lenMsg, "\n\n", 2);
	if (headersEnd == NULL) return;
	headersEnd += 2;

	const char *ct = strcasestr(*msg, "\nContent-Type:");
	if (ct == NULL || ct > headersEnd) return;
	ct += 14;

	if (strncasecmp(ct, "multipart/", 10) == 0) {
		char *firstBoundBegin = strcasestr(ct + 10, "boundary=");
		if (firstBoundBegin == NULL || firstBoundBegin > headersEnd) return;
		firstBoundBegin += 9;
		char *firstBound;
		const char *firstBoundEnd;

		if (firstBoundBegin[0] == '"') {
			firstBoundBegin++;
			firstBoundEnd = strchr(firstBoundBegin, '"');
		} else if (firstBoundBegin[0] == '\'') {
			firstBoundBegin++;
			firstBoundEnd = strchr(firstBoundBegin, '\'');
		} else {
			firstBoundEnd = strpbrk(firstBoundBegin, "; \t\v\f\r\n");
		}

		if (firstBoundEnd == NULL) return;

		firstBound = malloc(4 + (firstBoundEnd - firstBoundBegin));
		memcpy(firstBound + 3, firstBoundBegin, firstBoundEnd - firstBoundBegin);
		firstBound[0] = '\n';
		firstBound[1] = '-';
		firstBound[2] = '-';
		firstBound[3 + (firstBoundEnd - firstBoundBegin)] = '\0';

		size_t lenNew;
		char * const new = decodeMp(*msg, &lenNew, email, firstBound);

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
		size_t lenCs = 0;
		const char *cs = strcasestr(ct, "charset=");
		if (cs == NULL) cs = strcasestr(ct, "harset =");
		if (cs == NULL) cs = strcasestr(ct, "harset\t=");
		if (cs != NULL && cs < headersEnd) {
			const char *csEnd;
			cs += 8;

			if (cs[0] == '"') {
				cs++;
				csEnd = strchr(cs, '"');
			} else if (cs[0] == '\'') {
				cs++;
				csEnd = strchr(cs, '\'');
			} else {
				csEnd = strpbrk(cs, "; \t\v\f\r\n");
			}

			charset = strndup(cs, csEnd - cs);
		}

		const char *cte = strcasestr(*msg, "\nContent-Transfer-Encoding:quoted-printable");
		if (cte != NULL && cte < headersEnd) {
			size_t len = (*lenMsg) - (headersEnd - *msg);
			const size_t lenOld = len;
			decodeQuotedPrintable(headersEnd, &len);
			const size_t lenDiff = lenOld - len;
			*lenMsg -= lenDiff;
		} else {
			cte = strcasestr(*msg, "\nContent-Transfer-Encoding:base64");
			if (cte != NULL && cte < headersEnd) {
				const size_t lenOld = *lenMsg - (headersEnd - *msg);
				size_t lenDec;
				unsigned char * const dec = malloc(lenOld);
				if (dec != NULL && sodium_base642bin(dec, lenOld, headersEnd, lenOld, " \t\v\f\r\n", &lenDec, NULL, sodium_base64_VARIANT_ORIGINAL) == 0) {
					memcpy(headersEnd, dec, lenDec);
					*lenMsg -= lenOld - lenDec;
					free(dec);
				}
			}
		}

		// TODO: Support detecting charset if missing?
		if (charset != NULL && !isUtf8(charset, lenCs)) {
			char cs8[lenCs + 1];
			memcpy(cs8, charset, lenCs);
			cs8[lenCs] = '\0';

			int lenUtf8;
			const ssize_t lenOld = (*msg + *lenMsg) - headersEnd;
			char * const utf8 = toUtf8(headersEnd, lenOld, &lenUtf8, cs8);
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
					*lenMsg += (lenUtf8 - lenOld);
				}

				headersEnd = memmem(*msg,  *lenMsg, "\n\n", 2);
			}
		}

		if (charset != NULL) free(charset);

		removeControlChars((unsigned char*)(*msg), lenMsg);
		convertNbsp(*msg, lenMsg);

		ct = strcasestr(*msg, "\nContent-Type:");
		if (strncasecmp(ct + 14, "text/html", 9) == 0) {
			size_t lenHe = (*msg + *lenMsg) - headersEnd;
			const size_t lenOld = lenHe;
			htmlToText(headersEnd, &lenHe);
			*lenMsg -= (lenOld - lenHe);
		}
	}
}
