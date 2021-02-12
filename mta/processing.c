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

#define AEM_LIMIT_MULTIPARTS 50
#define AEM_CHAR_HEADERS_END 0x1e // Record Separator

static void removeHeaderSpace(unsigned char * msg, size_t const lenMsg) {
	if (lenMsg < 5) return;

	const unsigned char *c = msg;
	while (c != NULL) {
		const unsigned char * const next = memchr(c + 1, '\n', (msg + lenMsg) - (c + 1));

		const unsigned char * const colon = memchr(c + 1, ':', (msg + lenMsg) - (c + 1));
		if (colon == NULL) break;

		for (int i = (colon + 1) - msg; i < next - msg; i++) {
			if (isspace(msg[i])) msg[i] = 127; else break; // 127=del
		}

		c = next;
	}
}

static void compressSpaces(unsigned char * msg, size_t const lenMsg) {
	if (msg == NULL || lenMsg < 5) return;

	for (size_t i = 0; i < lenMsg - 1; i++) {
		if (isspace(msg[i]) && isspace(msg[i + 1])) msg[i] = 127; // Delete
	}
}

static void unfoldHeaders(unsigned char * const data, const size_t lenData) {
	while(1) {
		char * const lfSp = memmem(data + 2, lenData - 2, "\n ", 2);
		if (lfSp == NULL) break;
		*lfSp = 127; // Delete
	}
}

int getHeaders(unsigned char * const data, size_t * const lenData, struct emailInfo * const email) {
	if (data == NULL) return -1;

	unsigned char *hend = memmem(data, *lenData, "\r\n\r\n", 4);
	unsigned char *hend2 = memmem(data, *lenData, "\n\n", 2);
	if (hend == NULL || (hend2 != NULL && hend2 < hend)) hend = hend2;
	if (hend == NULL) return -1;
	const size_t lenHend = (hend == hend2) ? 2 : 4;

	email->lenHead = hend - data;
	if (email->lenHead < 5) {email->lenHead = 0; return -1;}

	email->head = malloc(email->lenHead + 1);
	memcpy(email->head, data, email->lenHead);
	email->head[email->lenHead] = '\0';

	memmove(data, hend + lenHend, (data + *lenData) - (hend + lenHend));
	*lenData -= (email->lenHead + lenHend);

	// Processing
	removeControlChars(email->head, &email->lenHead);
	removeHeaderSpace(email->head, email->lenHead);
	compressSpaces(email->head, email->lenHead);
	removeControlChars(email->head, &email->lenHead);
	unfoldHeaders(email->head, email->lenHead);
	removeControlChars(email->head, &email->lenHead);
	return 0;
}

void moveHeader(unsigned char * const data, size_t * const lenData, const char * const needle, const size_t lenNeedle, unsigned char * const target, uint8_t * const lenTarget, const size_t limit) {
	unsigned char * const hdr = memmem(data, *lenData, needle, lenNeedle);
	if (hdr != NULL) {
		const unsigned char * const hdrEnd = memchr(hdr + lenNeedle, '\n', (data + *lenData) - (hdr + lenNeedle));
		if (hdrEnd != NULL) {
			if (target != NULL || lenTarget != NULL) {
				const size_t lenTgt = hdrEnd - (hdr + lenNeedle);
				if (lenTgt > limit) return;
				*lenTarget = lenTgt;
				memcpy(target, hdr + lenNeedle, *lenTarget);
			}

			const size_t lenMove = (data + *lenData) - hdrEnd;
			memmove(hdr, hdrEnd, lenMove);

			const size_t lenDelete = (hdrEnd - (hdr + lenNeedle)) + lenNeedle;
			*lenData -= lenDelete;
			data[*lenData] = '\0';
		}
	}
}

// Example: =?iso-8859-1?Q?=A1Hola,_se=F1or!?=
void decodeEncodedWord(unsigned char * const data, size_t * const lenData) {
	if (data == NULL || lenData == NULL || *lenData < 1) return;

	while(1) {
		unsigned char * const ew = memmem(data, *lenData, "=?", 2);
		if (ew == NULL) break;

		// Remove charset part
		unsigned char * const charsetEnd = memchr(ew + 2, '?', (data + *lenData) - (ew + 2));
		if (charsetEnd == NULL) break;
		if (charsetEnd[2] != '?') break;

		const size_t lenCs = charsetEnd - (ew + 2);
		char cs[lenCs + 1];
		memcpy(cs, (ew + 2), lenCs);
		cs[lenCs] = '\0';

		const char type = charsetEnd[1];
		unsigned char *ewText = charsetEnd + 3;

		const unsigned char * const ewEnd = memmem(ewText, *lenData - (ewText - data), "?=", 2);
		if (ewEnd == NULL) break;

		size_t lenEw = ewEnd - ew;
		size_t lenEwText = ewEnd - ewText;

		if (lenEwText == 0) {
			memmove(ew, ewEnd + 2, (data + *lenData) - (ewEnd + 2));
			*lenData -= (lenEw + 2);
			continue;
		}

		while(1) {
			unsigned char * const underscore = memchr(ewText, '_', lenEwText);
			if (underscore == NULL) break;
			*underscore = ' ';
		}

		if (type == 'Q' || type == 'q') {
			decodeQuotedPrintable(ewText, &lenEwText);
		} else if (type == 'B' || type == 'b') {
			unsigned char * const dec = malloc(lenEwText);
			size_t lenDec;
			if (dec == NULL || sodium_base642bin(dec, lenEwText, (char*)ewText, lenEwText, " \t\v\f\r\n", &lenDec, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {free(dec); break;}

			memcpy(ewText, dec, lenDec);
			lenEwText = lenDec;
			free(dec);
		} else break;

		size_t lenUtf8 = 0;
		unsigned char *utf8 = toUtf8(ewText, lenEwText, &lenUtf8, cs);
		if (utf8 == NULL) break;

		for (size_t i = 0; i < lenUtf8; i++) { // Replace all control characters with spaces
			if ((unsigned char)(utf8[i]) < 32 || (unsigned char)(utf8[i]) == 127) utf8[i] = ' '; // 127=DEL
		}

		trimSpace(utf8, &lenUtf8);

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

int getCte(const char * const h) {
	if (h == NULL) return MTA_PROCESSING_CTE_NONE;

	const char *cte = strcasestr(h, "\nContent-Transfer-Encoding:");
	if (cte == NULL) return MTA_PROCESSING_CTE_NONE;

	cte += 27;
	while (isspace(*cte)) cte++;

	if (strncasecmp(cte, "Quoted-Printable", 16) == 0) return MTA_PROCESSING_CTE_QP;
	if (strncasecmp(cte, "Base64", 6) == 0) return MTA_PROCESSING_CTE_B64;
	return MTA_PROCESSING_CTE_NONE;
}

unsigned char *decodeCte(const int cte, const unsigned char * const src, size_t * const lenSrc) {
	unsigned char *new;

	switch(cte) {
		case MTA_PROCESSING_CTE_QP:
			new = malloc(*lenSrc + 1);
			if (new == NULL) return NULL;
			memcpy(new, src, *lenSrc);
			decodeQuotedPrintable(new, lenSrc);
		break;

		case MTA_PROCESSING_CTE_B64:
			new = malloc(*lenSrc);
			if (new == NULL) return NULL;

			size_t lenNew;
			if (sodium_base642bin(new, *lenSrc, (char*)src, *lenSrc, " \t\v\f\r\n", &lenNew, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {free(new); return NULL;}
			*lenSrc = lenNew;
		break;

		default:
			new = malloc(*lenSrc + 1);
			if (new == NULL) return NULL;
			memcpy(new, src, *lenSrc);
	}

	new[*lenSrc] = '\0';
	return new;
}

unsigned char *decodeMp(const unsigned char * const src, size_t *outLen, struct emailInfo * const email, unsigned char * const bound0, const size_t lenBound0) {
	const size_t lenSrc = *outLen;

	unsigned char *out = NULL;
	*outLen = 0;

	int boundCount = 1;
	unsigned char *bound[AEM_LIMIT_MULTIPARTS];
	size_t lenBound[AEM_LIMIT_MULTIPARTS];
	bound[0] = bound0;
	lenBound[0] = lenBound0;

	const unsigned char *searchBegin = src;
	for (int i = 0; i < boundCount;) {
		const unsigned char *begin = memmem(searchBegin, (src + lenSrc) - searchBegin, bound[i], lenBound[i]);
		if (begin == NULL) break;

		begin += lenBound[i];

		if (begin[0] == '-' && begin[1] == '-' && begin[2] == '\r' && begin[3] == '\n') {
			searchBegin = src;
			i++;
			continue;
		}

		const unsigned char *hend = memmem(begin, (src + lenSrc) - begin, (unsigned char[]){'\r','\n','\r','\n'}, 4);
		if (hend == NULL) break;
		hend += 3;

		const size_t lenPartHeaders = hend - begin;
		if (lenPartHeaders > 9999) break;

		char partHeaders[lenPartHeaders + 1];
		memcpy(partHeaders, begin, lenPartHeaders);
		partHeaders[lenPartHeaders] = '\0';

		const char *ct = strcasestr(partHeaders, "Content-Type:");
		if (ct != NULL) {
			ct += 13;
			while (isspace(*ct)) ct++;
		}

		const char *fn = (ct == NULL) ? NULL : strcasestr(ct, "NAME=");
		size_t lenFn = 0;
		if (fn != NULL) {
			fn += 5;
			while (isspace(*fn)) fn++;

			if (*fn == '"' || *fn == '\'') fn++;
			while (isspace(*fn)) fn++;

			while (fn[lenFn] != '\0' && fn[lenFn] != '\'' && fn[lenFn] != '"') lenFn++;
			trimEnd((unsigned char*)fn, &lenFn);
		}

		const unsigned char *boundEnd = memmem(hend, (src + lenSrc) - hend, bound[i], lenBound[i]);
		if (boundEnd == NULL) break;

		size_t lenNew = boundEnd - hend;

		const bool isText = (ct != NULL) && (strncasecmp(ct, "text/", 5) == 0);
		const bool isHtml = isText && (strncasecmp(ct + 5, "html", 4) == 0);
		const bool ignore = (ct != NULL) && (strncasecmp(ct, "multipart", 9) == 0);

		if (ignore) {
			char *newBegin = strcasestr(ct + 10, "boundary=");
			if (newBegin != NULL) {
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
					if (bound[boundCount] == NULL) {syslog(LOG_ERR, "Failed allocation"); out = NULL; break;}

					bound[boundCount][0] = '\r';
					bound[boundCount][1] = '\n';
					bound[boundCount][2] = '-';
					bound[boundCount][3] = '-';
					memcpy(bound[boundCount] + 4, newBegin, newEnd - newBegin);
					lenBound[boundCount] = newEnd - newBegin + 4;

					boundCount++;
					if (boundCount >= AEM_LIMIT_MULTIPARTS) break;
				}
			}
		}

		char *charset = NULL;
		if (isText) {
			const unsigned char *cs = (unsigned char*)strcasestr((char*)ct + 14, "charset=");
			if (cs == NULL) cs = (unsigned char*)strcasestr((char*)ct + 14, "harset =");
			if (cs != NULL && cs < hend) {
				const unsigned char *csEnd;
				cs += 8;

				if (cs[0] == '"') {
					cs++;
					csEnd = (unsigned char*)strchr((char*)cs, '"');
				} else if (cs[0] == '\'') {
					cs++;
					csEnd = (unsigned char*)strchr((char*)cs, '\'');
				} else {
					csEnd = (unsigned char*)strpbrk((char*)cs, "; \t\v\f\r\n");
				}

				if (csEnd != NULL) {
					charset = malloc(csEnd - cs + 1); // TODO: check result
					memcpy(charset, cs, csEnd - cs);
					charset[csEnd - cs] = '\0';
				}
			}
		}

		const char cte = getCte(partHeaders);
		unsigned char *new = decodeCte(cte, hend, &lenNew);
		if (new == NULL) break;

		if (isText) {
			if (charset != NULL && !isUtf8(charset)) {
				size_t lenUtf8;
				unsigned char * const utf8 = toUtf8(new, lenNew, &lenUtf8, charset);
				if (utf8 != NULL) {
					free(new);
					new = utf8;
					lenNew = lenUtf8;
				}
			}
			if (charset != NULL) free(charset);

			convertNbsp(new, &lenNew);
			removeControlChars(new, &lenNew);
			if (isHtml) htmlToText((char*)new, &lenNew);

			trimBegin(new, &lenNew);
			trimEnd(new, &lenNew);
			new[lenNew] = '\0';

			if (*outLen == 0) {
				out = malloc(lenNew);
				if (out == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}
				memcpy(out, new, lenNew);
				*outLen += lenNew;
			} else {
				unsigned char * const out2 = realloc(out, *outLen + lenNew + 1);
				if (out2 == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}
				out = out2;

				out[*outLen] = '\x1f'; // Unit Seperator
				memcpy(out + *outLen + 1, new, lenNew);
				*outLen += lenNew + 1;
			}
		} else if (!ignore && email->attachCount < AEM_MAXNUM_ATTACHMENTS) {
			if (fn == NULL || lenFn < 1) {
				fn = (char[]){'A','E','M'}; // TODO, name based on message/sender/etc
				lenFn = 3;
			} else if (lenFn > 256) lenFn = 256;

			if (lenFn + lenNew <= 1048576) { // 1 MiB, TODO more exact
				email->attachment[email->attachCount] = malloc(17 + lenFn + lenNew);

				if (email->attachment[email->attachCount] != NULL) {
					email->attachment[email->attachCount][0] = (lenFn - 1);
					// 16 bytes reserved for MsgId
					memcpy(email->attachment[email->attachCount] + 17, fn, lenFn);
					memcpy(email->attachment[email->attachCount] + 17 + lenFn, new, lenNew);

					email->lenAttachment[email->attachCount] = 17 + lenFn + lenNew;
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
