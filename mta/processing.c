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

#include "date.h"

#include "processing.h"

#define AEM_LIMIT_MULTIPARTS 50
#define AEM_CHAR_HEADERS_END 0x1e // Record Separator

// "abc" <def@ghj> --> abc\rdef@ghj
static void minifyHeaderAddress(unsigned char *source, uint8_t * const lenSource) {
	while(1) {
		unsigned char *r = memchr(source, '\r', *lenSource);
		if (r == NULL) break;
		*r = ' ';
	}

	unsigned char *addrStart = memchr(source, '<', *lenSource);
	unsigned char *addrEnd = memchr(source, '>', *lenSource);
	if (addrStart == NULL || addrEnd == NULL || addrEnd < addrStart) return;
	addrStart++;
	const size_t lenAddr = addrEnd - addrStart;

	if (addrStart == source + 1) {
		memmove(source, addrStart, lenAddr);
		*lenSource = lenAddr;
		return;
	}

	unsigned char *nameEnd = addrStart - 1;
	unsigned char *nameStart = source;
	while (isspace(*nameStart) && nameStart[1] != '<') nameStart++;

	const bool quot = (*nameStart == '"');
	if (quot) nameStart++;

	if (nameStart == nameEnd) {
		memmove(source, addrStart, lenAddr);
		*lenSource = lenAddr;
		return;
	}

	size_t lenName = nameEnd - nameStart;
	while (lenName > 0 && isspace(nameStart[lenName - 1])) lenName--;

	if (quot && lenName > 0 && nameStart[lenName - 1] == '"') lenName--;

	if (lenName < 1) {
		memcpy(source, addrStart, lenAddr);
		*lenSource = lenAddr;
		return;
	}

	unsigned char new[255];
	memcpy(new, nameStart, lenName);
	new[lenName] = '\r';
	memcpy(new + lenName + 1, addrStart, lenAddr);

	*lenSource = lenName + 1 + lenAddr;
	memcpy(source, new, *lenSource);
	return;
}

static void removeHeaderSpace(unsigned char * msg, size_t const lenMsg) {
	if (lenMsg < 5) return;

	const unsigned char *c = msg;
	while (c != NULL) {
		const unsigned char * const next = memchr(c + 1, '\n', (msg + lenMsg) - (c + 1));
		const unsigned char * const colon = memchr(c + 1, ':', (msg + lenMsg) - (c + 1));
		if (colon == NULL) break;

		for (int i = (colon + 1) - msg; i < ((next != NULL) ? next - msg : (int)lenMsg); i++) {
			if (isspace(msg[i])) msg[i] = 127; else break; // 127=del
		}

		c = next;
	}
}

static void unfoldHeaders(unsigned char * const data, const size_t lenData) {
	while(1) {
		char *t = memchr(data, '\t', lenData);
		if (t == NULL) break;
		*t = ' ';
	}

	while(1) {
		char * const lfSp = memmem(data, lenData, (unsigned char[]){'\n',' '}, 2);
		if (lfSp == NULL) break;
		*lfSp = 127; // DEL
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

	unfoldHeaders(email->head, email->lenHead);
	removeHeaderSpace(email->head, email->lenHead);

	// Preserve first linebreak
	email->lenHead--;
	cleanText(email->head + 1, &email->lenHead);
	email->lenHead++;

	email->head[email->lenHead] = '\0';
	return 0;
}

void moveHeader(unsigned char * const data, size_t * const lenData, const char * const needle, const size_t lenNeedle, unsigned char * const target, uint8_t * const lenTarget, const size_t limit) {
	unsigned char * const hdr = (unsigned char*)strcasestr((char*)data, needle);
	if (hdr == NULL) return;

	const unsigned char *hdrEnd = memchr(hdr + lenNeedle, '\n', (data + *lenData) - (hdr + lenNeedle));
	if (hdrEnd == NULL) hdrEnd = data + *lenData;

	if (target != NULL && lenTarget != NULL) {
		const size_t lenTgt = hdrEnd - (hdr + lenNeedle);
		if (lenTgt > limit) return;
		*lenTarget = lenTgt;
		memcpy(target, hdr + lenNeedle, *lenTarget);
	}

	const size_t lenMove = (data + *lenData) - hdrEnd;
	if (lenMove > 0) memmove(hdr, hdrEnd, lenMove);

	const size_t lenDelete = (hdrEnd - (hdr + lenNeedle)) + lenNeedle;
	*lenData -= lenDelete;
	data[*lenData] = '\0';
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

static int getCte(const char * const h) {
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

void convertToUtf8(unsigned char ** const src, size_t * const lenSrc, const char * const charset) {
	if (src == NULL || *src == NULL || charset == NULL || isUtf8(charset)) return;

	size_t lenUtf8;
	unsigned char * const utf8 = toUtf8(*src, *lenSrc, &lenUtf8, charset);
	if (utf8 == NULL) return;

	free(*src);
	*src = utf8;
	*lenSrc = lenUtf8;
}

char *getCharset(const char *ct) {
	const char *cs = strcasestr(ct, "charset");
	if (cs == NULL) return NULL;
	cs = strchr(cs + 7, '=');
	if (cs == NULL) return NULL;
	cs++;
	while (isspace(*cs)) cs++;

	char *csEnd;
	if (*cs == '"' || *cs == '\'') {
		csEnd = strchr(cs + 1, *cs);
		cs++;
	} else {
		csEnd = strpbrk(cs, "; \t\v\f\r\n");
	}
	if (csEnd == NULL) return NULL;

	const size_t lenCs = csEnd - cs;
	char *charset = malloc(lenCs + 1);
	if (charset == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}

	memcpy(charset, cs, lenCs);
	charset[lenCs] = '\0';
	return charset;
}

unsigned char* getBound(const char * const src, size_t * const lenBound) {
	const char *start = strcasestr(src, "boundary");
	if (start == NULL) return NULL;
	start = strchr(start + 8, '=');
	if (start == NULL) return NULL;
	start++;

	const char *end = NULL;
	if (*start == '"' || *start == '\'') {
		end = strchr(start + 1, *start);
		start++;
	} else {
		end = strpbrk(start, "; \t\v\f\r\n");
	}

	*lenBound = 4 + ((end != NULL) ? end : src + strlen(src)) - start;
	unsigned char *bound = malloc(*lenBound);
	bound[0] = '\r';
	bound[1] = '\n';
	bound[2] = '-';
	bound[3] = '-';
	memcpy(bound + 4, start, *lenBound - 4);
	return bound;
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
		const unsigned char *begin = memmem(searchBegin, (src + lenSrc) - searchBegin, bound[i] + ((i == 0) ? 2 : 0), lenBound[i]);
		if (begin == NULL) break;

		begin += lenBound[i];

		if (begin[0] == '-' && begin[1] == '-') {
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
		}

		const unsigned char *boundEnd = memmem(hend, (src + lenSrc) - hend, bound[i], lenBound[i]);
		if (boundEnd == NULL) break;

		size_t lenNew = boundEnd - hend;

		const bool isText = (ct != NULL) && (strncasecmp(ct, "text/", 5) == 0);
		const bool isHtml = isText && (strncasecmp(ct + 5, "html", 4) == 0);
		const bool multip = (ct != NULL) && (strncasecmp(ct, "multipart", 9) == 0);

		if (multip) {
			bound[boundCount] = getBound(ct + 9, lenBound + boundCount);

			if (bound[boundCount] != NULL) {
				boundCount++;
				if (boundCount >= AEM_LIMIT_MULTIPARTS) break;
			}
		}

		const char cte = getCte(partHeaders);
		unsigned char *new = decodeCte(cte, hend, &lenNew);
		if (new == NULL) break;

		if (isText) {
			char * const cs = getCharset(ct);
			convertToUtf8(&new, &lenNew, cs);
			if (cs != NULL) free(cs);

			if (isHtml) htmlToText((char*)new, &lenNew);

			cleanText(new, &lenNew);
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

				out[*outLen] = '\r';
				memcpy(out + *outLen + 1, new, lenNew);
				*outLen += lenNew + 1;
			}
		} else if (!multip && email->attachCount < AEM_MAXNUM_ATTACHMENTS) {
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

void processEmail(unsigned char *source, size_t * const lenSource, struct emailInfo * const email) {
	if (getHeaders(source, lenSource, email) != 0) return;

	decodeEncodedWord(email->head, &email->lenHead);
	moveHeader(email->head, &email->lenHead, "\nFrom:", 6, email->headerFrom, &email->lenHeaderFrom, 255);
	moveHeader(email->head, &email->lenHead, "\nTo:", 4, email->headerTo, &email->lenHeaderTo, 127);
	moveHeader(email->head, &email->lenHead, "\nSubject:", 9, email->subject, &email->lenSubject, 255);

	minifyHeaderAddress(email->headerFrom, &email->lenHeaderFrom);
	minifyHeaderAddress(email->headerTo, &email->lenHeaderTo);

	char ct[256];
	uint8_t lenCt = 0;
	moveHeader(email->head, &email->lenHead, "\nContent-Type:", 14, (unsigned char*)ct, &lenCt, 255);
	ct[lenCt] = '\0';

	uint8_t lenHdrDate = 0;
	unsigned char hdrDate[256];
	moveHeader(email->head, &email->lenHead, "\nDate:", 6, hdrDate, &lenHdrDate, 255);
	hdrDate[lenHdrDate] = '\0';
	const time_t hdrTime = (lenHdrDate == 0) ? 0 : smtp_getTime((char*)hdrDate, &email->headerTz);

	if (hdrTime > 0) {
		// Store the difference between received and header timestamps (-18h .. +736s)
		const time_t timeDiff = (time_t)email->timestamp + 736 - hdrTime; // 736 = 2^16 % 3600
		email->headerTs = (timeDiff > UINT16_MAX) ? UINT16_MAX : ((timeDiff < 0) ? 0 : timeDiff);
	}

	uint8_t lenHdrMsgId = 0;
	unsigned char hdrMsgId[256];
	moveHeader(email->head, &email->lenHead, "\nMessage-ID:", 12, hdrMsgId, &lenHdrMsgId, 255);
	if (lenHdrMsgId > 0) {
		if (hdrMsgId[lenHdrMsgId - 1] == '>') lenHdrMsgId--;
		if (hdrMsgId[0] == '<') {
			memcpy(email->msgId, hdrMsgId + 1, lenHdrMsgId - 1);
			email->lenMsgId = lenHdrMsgId - 1;
		} else {
			memcpy(email->msgId, hdrMsgId, lenHdrMsgId);
			email->lenMsgId = lenHdrMsgId;
		}
	}

	// Content-Type
	if (strncmp(ct, "multipart", 9) == 0) {
		size_t lenBound;
		unsigned char * const bound = getBound(ct + 9, &lenBound);

		if (bound != NULL) {
			email->lenBody = *lenSource;
			email->body = decodeMp(source, &(email->lenBody), email, bound, lenBound - 2);
			// bound is free'd by decodeMp()

			if (email->body == NULL) { // Error - decodeMp() failed
				email->body = source;
				email->lenBody = *lenSource;
			} else free(source);
		} else { // Error - getBound() failed
			email->body = source;
			email->lenBody = *lenSource;
		}
	} else { // Single-part body
		email->body = source;
		email->lenBody = *lenSource;

		char tmp[256];
		uint8_t lenTmp = 0;
		moveHeader(email->head, &email->lenHead, "\nContent-Transfer-Encoding:", 27, (unsigned char*)tmp, &lenTmp, 255);
		tmp[lenTmp] = '\0';

		int cte;
		if (strcasestr(tmp, "quoted-printable") != 0) cte = MTA_PROCESSING_CTE_QP;
		else if (strcasestr(tmp, "base64") != 0) cte = MTA_PROCESSING_CTE_B64;
		else cte = 0;

		unsigned char * const new = decodeCte(cte, email->body, &email->lenBody);
		if (new != NULL) {
			free(email->body);
			email->body = new;
		}

		if (strncasecmp(ct, "text/", 5) == 0) {
			char * const cs = getCharset(ct);
			convertToUtf8(&email->body, &email->lenBody, cs);
			if (cs != NULL) free(cs);

			if (strncasecmp(ct + 5, "html", 4) == 0) htmlToText((char*)email->body, &email->lenBody);

			cleanText(email->body, &email->lenBody);
			email->body[email->lenBody] = '\0';
		}
	}
}
