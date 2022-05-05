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
#include "../Common/ValidUtf8.h"
#include "../Common/memeq.h"

#include "date.h"

#include "processing.h"

#define AEM_LIMIT_MULTIPARTS 50

#define MTA_PROCESSING_CTE_NONE 0
#define MTA_PROCESSING_CTE_B64 1
#define MTA_PROCESSING_CTE_QP 2

// "abc" <def@ghj> --> abcAEM_CET_CHAR_SEPdef@ghj
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
	new[lenName] = AEM_CET_CHAR_SEP;
	memcpy(new + lenName + 1, addrStart, lenAddr);

	*lenSource = lenName + 1 + lenAddr;
	memcpy(source, new, *lenSource);
	return;
}

static void replace(unsigned char * const target, size_t * const lenTarget, const unsigned char * const source, const size_t lenSource) {
	memcpy(target, source, lenSource);
	*lenTarget = lenSource;
}

#define AEM_CLEANHEADERS_MAXLENOUT 65536
static void cleanHeaders(unsigned char * const data, size_t * const lenData) {
	unsigned char out[AEM_CLEANHEADERS_MAXLENOUT];
	size_t lenOut = 0;

	bool wasEw = false;
	bool afterColon = false;

	for (size_t i = 0; i < *lenData; i++) {
		if (i < *lenData - 1 && data[i] == '=' && data[i + 1] == '?') { // Encoded-Word; e.g. =?iso-8859-1?Q?=A1Hola,_se=F1or!?=
			if (wasEw && lenOut > 0) {
				// This is EW follows another: remove all spaces between the two
				while (lenOut > 0 && isspace(out[lenOut - 1])) lenOut--;
			}

			const unsigned char * const charsetEnd = memchr(data + i + 2, '?', *lenData - (i + 2));
			const size_t lenCharset = (charsetEnd == NULL) ? 0 : charsetEnd - (data + i + 2);
			if (lenCharset < 1 || lenCharset > 30) return replace(data, lenData, out, lenOut);

			char charset[lenCharset + 1];
			memcpy(charset, data + i + 2, lenCharset);
			charset[lenCharset] = '\0';

			if (data[i + 2 + lenCharset] != '?' || data[i + 4 + lenCharset] != '?') return replace(data, lenData, out, lenOut);

			const bool isBase64 = (toupper(data[i + 3 + lenCharset]) == 'B');
			if (!isBase64 && toupper(data[i + 3 + lenCharset]) != 'Q') return replace(data, lenData, out, lenOut);

			const unsigned char * const ewStart = data + i + 5 + lenCharset;
			const unsigned char * const ewEnd = memmem(ewStart, *lenData - (i + 5 + lenCharset), "?=", 2);
			const size_t lenEw = (ewEnd == NULL) ? 0 : ewEnd - ewStart;
			if (lenEw < 1) return replace(data, lenData, out, lenOut);

			size_t lenDec = 0;
			unsigned char dec[lenEw];

			if (isBase64) {
				if (sodium_base642bin(dec, lenEw, (char*)ewStart, lenEw, " \t\v\f\r\n", &lenDec, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) return replace(data, lenData, out, lenOut);
			} else {
				memcpy(dec, ewStart, lenEw);
				lenDec = lenEw;

				// RFC 2047 4.2: underscore always represents hexadecimal 20
				for (size_t j = 0; j < lenDec; j++) {
					if (dec[j] == '_') dec[j] = ' ';
				}

				decodeQuotedPrintable(dec, &lenDec);
			}

			const size_t lenOriginal = 7 + lenCharset + lenEw;

			if (isUtf8(charset)) {
				filterUtf8(dec, lenDec, false);

				if (lenDec <= lenOriginal) {
					if (lenOut + lenDec >= AEM_CLEANHEADERS_MAXLENOUT) return;
					memcpy(out + lenOut, dec, lenDec);
					lenOut += lenDec;
				} else {
					if (lenOut + lenOriginal >= AEM_CLEANHEADERS_MAXLENOUT) return;
					memset(out + lenOut, '?', lenOriginal);
					lenOut += lenOriginal;
				}
			} else {
				size_t lenDecUtf8 = 0;
				unsigned char *decUtf8 = (unsigned char*)toUtf8((char*)dec, lenDec, &lenDecUtf8, charset);

				if (decUtf8 != NULL && lenDecUtf8 > 0 && lenDecUtf8 <= lenOriginal) {
					filterUtf8(decUtf8, lenDecUtf8, false);

					if (lenOut + lenDecUtf8 >= AEM_CLEANHEADERS_MAXLENOUT) return;
					memcpy(out + lenOut, decUtf8, lenDecUtf8);
					lenOut += lenDecUtf8;
				} else {
					if (lenOut + lenOriginal >= AEM_CLEANHEADERS_MAXLENOUT) return;
					memset(out + lenOut, '?', lenOriginal);
					lenOut += lenOriginal;
				}

				if (decUtf8 != NULL) free(decUtf8);
			}

			i += lenOriginal;

			wasEw = true;
		} else if (i < (*lenData - 1) && data[i] == '\n' && isspace(data[i + 1])) {
			// This linebreak is followed by a space -> unfold the header by ignoring this linebreak
			continue;
		} else if (data[i] == '\n') {
			if (lenOut > 0 && out[lenOut - 1] == ' ') lenOut--;

			if (lenOut + 1 >= AEM_CLEANHEADERS_MAXLENOUT) return;
			out[lenOut] = '\n';
			lenOut++;

			afterColon = false;
		} else if (data[i] == ' ' || data[i] == '\t') {
			if (lenOut < 1 || out[lenOut - 1] != ' ') {
				if (lenOut + 1 >= AEM_CLEANHEADERS_MAXLENOUT) return;
				out[lenOut] = ' ';
				lenOut++;
			}
		} else if (!afterColon && data[i] == ':') {
			if (i < (*lenData - 1) && (data[i + 1] == ' ' || data[i + 1] == '\t')) i++; // Skip space after header name (colon)

			if (lenOut + 1 >= AEM_CLEANHEADERS_MAXLENOUT) return;
			out[lenOut] = ':';
			lenOut++;

			afterColon = true;
		} else if (data[i] > 32 && data[i] < 127) {

			if (lenOut + 1 >= AEM_CLEANHEADERS_MAXLENOUT) return;
			out[lenOut] = data[i];
			lenOut++;

			wasEw = false;
		} // else skipped
	}

	replace(data, lenData, out, lenOut);
}

static int getHeaders(unsigned char * const data, size_t * const lenData, struct emailInfo * const email) {
	if (data == NULL || *lenData < 1) return -1;

	unsigned char *hend = memmem(data, *lenData, "\r\n\r\n", 4);
	unsigned char *hend2 = memmem(data, *lenData, "\n\n", 2);
	if (hend == NULL || (hend2 != NULL && hend2 < hend)) hend = hend2;
	if (hend == NULL) return -1;
	const size_t lenHend = (hend == hend2) ? 2 : 4;

	email->lenHead = hend - data;
	if (email->lenHead < 5) {email->lenHead = 0; return -1;}

	email->head = malloc(email->lenHead + 1);
	if (email->head == NULL) {syslog(LOG_ERR, "Failed allocation"); email->lenHead = 0; return -1;}
	memcpy(email->head, data, email->lenHead);
	email->head[email->lenHead] = '\0';

	memmove(data, hend + lenHend, (data + *lenData) - (hend + lenHend));
	*lenData -= (email->lenHead + lenHend);

	cleanHeaders(email->head, &email->lenHead);

	email->head[email->lenHead] = '\0';
	return 0;
}

static void moveHeader(unsigned char * const data, size_t * const lenData, const char * const needle, const size_t lenNeedle, unsigned char * const target, uint8_t * const lenTarget, const size_t limit) {
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

static int getCte(const unsigned char * const h, const size_t len) {
	if (h == NULL) return MTA_PROCESSING_CTE_NONE;

	const unsigned char *cte = memcasemem(h, len, "\nContent-Transfer-Encoding:", 27);
	if (cte == NULL) return MTA_PROCESSING_CTE_NONE;
	cte += 27;

	if (memeq_anycase(cte, "Quoted-Printable", 16)) return MTA_PROCESSING_CTE_QP;
	if (memeq_anycase(cte, "Base64", 6)) return MTA_PROCESSING_CTE_B64;
	return MTA_PROCESSING_CTE_NONE;
}

static unsigned char *decodeCte(const int cte, const unsigned char * const src, size_t * const lenSrc) {
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

static void convertToUtf8(char ** const src, size_t * const lenSrc, const char * const charset) {
	if (src == NULL || *src == NULL || charset == NULL || isUtf8(charset)) return;

	size_t lenUtf8;
	char * const utf8 = toUtf8(*src, *lenSrc, &lenUtf8, charset);
	if (utf8 == NULL) return;

	free(*src);
	*src = utf8;
	*lenSrc = lenUtf8;
}

static unsigned char *getCharset(const unsigned char *ct, const size_t lenCt) {
	const unsigned char *cs = memcasemem(ct, lenCt, "charset", 7);
	if (cs == NULL) return NULL;
	cs = memchr(cs + 7, '=', (ct + lenCt) - (cs + 7));
	if (cs == NULL) return NULL;

	while(1) {
		cs++;
		if (cs == ct + lenCt) return NULL;

		if (isspace(*cs)) break;
	}

	const unsigned char *csEnd;
	if (*cs == '"' || *cs == '\'') {
		csEnd = memchr(cs + 1, *cs, (ct + lenCt) - (cs + 1));
		if (csEnd == NULL) return NULL;
		cs++;
	} else {
		csEnd = mempbrk(cs, (ct + lenCt) - cs, (unsigned char[]){';', ' ', '\t', '\v', '\f', '\r', '\n'}, 7);
		if (csEnd == NULL) csEnd = ct + lenCt;
	}

	const size_t lenCs = csEnd - cs;
	unsigned char * const charset = malloc(lenCs + 1);
	if (charset == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}

	memcpy(charset, cs, lenCs);
	charset[lenCs] = '\0';
	return charset;
}

static unsigned char* getBound(const unsigned char * const src, const size_t lenSrc, size_t * const lenBound) {
	const unsigned char *start = memcasemem(src, lenSrc, "boundary", 8);
	if (start == NULL) return NULL;
	start = memchr(start + 8, '=', (src + lenSrc) - (start + 8));
	if (start == NULL) return NULL;
	start++;

	const unsigned char *end = NULL;
	if (*start == '"' || *start == '\'') {
		end = memchr(start + 1, *start, (src + lenSrc) - (start + 1));
		start++;
	} else {
		end = mempbrk(start, (src + lenSrc) - start, (unsigned char[]){';', ' ', '\t', '\v', '\f', '\r', '\n'}, 7);
	}

	*lenBound = 4 + ((end != NULL) ? end : src + lenSrc) - start;
	unsigned char *bound = malloc(*lenBound);
	if (bound == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}
	bound[0] = '\r';
	bound[1] = '\n';
	bound[2] = '-';
	bound[3] = '-';
	memcpy(bound + 4, start, *lenBound - 4);
	return bound;
}

static size_t getNameHeader(const unsigned char * const src, const size_t lenSrc, unsigned char * const target) {
	target[0] = '?';
	if (src == NULL || lenSrc < 6) return 1;

	const unsigned char *fn = memcasemem(src, lenSrc, "NAME=", 5);
	if (fn == NULL) return 1;

	fn += 5;
	while (isspace(*fn)) {
		fn++;
		if (fn == src + lenSrc) return 1;
	}

	const unsigned char *end;
	if (*fn == '"' || *fn == '\'') {
		fn++;
		end = mempbrk(fn, (src + lenSrc) - fn, (const unsigned char[]){*(fn - 1), '\v', '\r', '\n', '\0'}, 4);
		if (end == NULL) return 1;
	} else {
		end = mempbrk(fn, (src + lenSrc) - fn, (const unsigned char[]){'\v', '\r', '\n', '\0', '\t', ' ', ';'}, 7);
		if (end == NULL) return 1;
	}

	const size_t lenFn = end - fn;
	if (lenFn > 255) return 1;
	memcpy(target, fn, lenFn);
	return lenFn;
}

static unsigned char *decodeMp(const unsigned char * const src, size_t *outLen, struct emailInfo * const email, unsigned char * const bound0, const size_t lenBound0) {
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

		size_t lenPartHeaders = hend - begin;
		if (lenPartHeaders > 9999) break;

		unsigned char partHeaders[lenPartHeaders];
		memcpy(partHeaders, begin, lenPartHeaders);
		cleanHeaders(partHeaders, &lenPartHeaders);

		const unsigned char *ct = memcasemem(partHeaders, lenPartHeaders, "Content-Type:", 13);
		if (ct != NULL) ct += 13;

		unsigned char fn[256];
		const size_t lenFn = getNameHeader(ct, (partHeaders + lenPartHeaders) - ct, fn);

		const unsigned char *boundEnd = memmem(hend, (src + lenSrc) - hend, bound[i], lenBound[i]);
		if (boundEnd == NULL) break;

		size_t lenNew = boundEnd - hend;

		const bool isText = (ct != NULL) && (memeq_anycase(ct, "text/", 5));
		const bool isHtml = isText && (memeq_anycase(ct + 5, "html", 4));
		const bool multip = (ct != NULL) && (memeq_anycase(ct, "multipart", 9));

		if (multip) {
			bound[boundCount] = getBound(ct + 9, (partHeaders + lenPartHeaders) - (ct + 9), lenBound + boundCount);

			if (bound[boundCount] != NULL) {
				boundCount++;
				if (boundCount >= AEM_LIMIT_MULTIPARTS) break;
			}
		}

		const unsigned char cte = getCte(partHeaders, lenPartHeaders);
		unsigned char *new = decodeCte(cte, hend, &lenNew);
		if (new == NULL) break;

		if (isText) {
			unsigned char * const cs = getCharset(ct, (partHeaders + lenPartHeaders) - ct);
			convertToUtf8((char**)&new, &lenNew, (char*)cs);
			if (cs != NULL) free(cs);

			if (isHtml) htmlToText((char*)new, &lenNew);

			cleanText(new, &lenNew, !isHtml);
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

				out[*outLen] = AEM_CET_CHAR_SEP;
				memcpy(out + *outLen + 1, new, lenNew);
				*outLen += lenNew + 1;
			}
		} else if (!multip && email->attachCount < AEM_MAXNUM_ATTACHMENTS) {
			const size_t lenAtt = 17 + lenFn + lenNew;
			if (lenAtt <= AEM_API_BOX_SIZE_MAX) {
				email->attachment[email->attachCount] = malloc(lenAtt);

				if (email->attachment[email->attachCount] != NULL) {
					email->attachment[email->attachCount][0] = (lenFn - 1);
					// 16 bytes reserved for MsgId
					memcpy(email->attachment[email->attachCount] + 17, fn, lenFn);
					memcpy(email->attachment[email->attachCount] + 17 + lenFn, new, lenNew);

					email->lenAttachment[email->attachCount] = lenAtt;
					(email->attachCount)++;
				} else syslog(LOG_ERR, "Failed allocation");
			} // else attachment too large
		}

		free(new);
		searchBegin = boundEnd;
	}

	for (int i = 0; i < boundCount; i++) free(bound[i]);
	return out;
}

void processEmail(unsigned char *source, size_t * const lenSource, struct emailInfo * const email) {
	if (getHeaders(source, lenSource, email) != 0) return;

	moveHeader(email->head, &email->lenHead, "\nMIME-Version:", 14, email->hdrFr, &email->lenHdrFr, 255); // Removed/ignored
	moveHeader(email->head, &email->lenHead, "\nFrom:",          6, email->hdrFr, &email->lenHdrFr, 255);
	moveHeader(email->head, &email->lenHead, "\nReply-To:",     10, email->hdrRt, &email->lenHdrRt, 255);
	moveHeader(email->head, &email->lenHead, "\nTo:",            4, email->hdrTo, &email->lenHdrTo, 63);
	moveHeader(email->head, &email->lenHead, "\nSubject:",       9, email->sbjct, &email->lenSbjct, 255);

	minifyHeaderAddress(email->hdrFr, &email->lenHdrFr);
	minifyHeaderAddress(email->hdrRt, &email->lenHdrRt);
	minifyHeaderAddress(email->hdrTo, &email->lenHdrTo);

	unsigned char ct[255];
	uint8_t lenCt = 0;
	moveHeader(email->head, &email->lenHead, "\nContent-Type:", 14, (unsigned char*)ct, &lenCt, 255);

	uint8_t lenHdrDate = 0;
	unsigned char hdrDate[256];
	moveHeader(email->head, &email->lenHead, "\nDate:", 6, hdrDate, &lenHdrDate, 255);
	hdrDate[lenHdrDate] = '\0';
	const time_t hdrTime = (lenHdrDate == 0) ? 0 : smtp_getTime((char*)hdrDate, &email->hdrTz);

	if (hdrTime > 0) {
		// Store the difference between received and header timestamps (-18h .. +736s)
		const time_t timeDiff = (time_t)email->timestamp + 736 - hdrTime; // 736 = 2^16 % 3600
		email->hdrTs = (timeDiff > UINT16_MAX) ? UINT16_MAX : ((timeDiff < 0) ? 0 : timeDiff);
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
	if (lenCt == 9 && memeq_anycase(ct, "multipart", 9)) {
		// CTE in headers: ignored
		unsigned char ignore[255];
		uint8_t lenIgnore;
		moveHeader(email->head, &email->lenHead, "\nContent-Transfer-Encoding:", 27, ignore, &lenIgnore, 255);

		size_t lenBound;
		unsigned char * const bound = getBound(ct + 9, lenCt - 9, &lenBound);

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

		unsigned char tmp[255];
		uint8_t lenTmp = 0;
		moveHeader(email->head, &email->lenHead, "\nContent-Transfer-Encoding:", 27, (unsigned char*)tmp, &lenTmp, 255);

		int cte;
		if (memcasemem(tmp, lenTmp, "quoted-printable", 16) != NULL) cte = MTA_PROCESSING_CTE_QP;
		else if (memcasemem(tmp, lenTmp, "base64", 6) != NULL) cte = MTA_PROCESSING_CTE_B64;
		else cte = 0;

		unsigned char * const new = decodeCte(cte, email->body, &email->lenBody);
		if (new != NULL) {
			free(email->body);
			email->body = new;
		}

		if (lenCt < 2 || memeq_anycase(ct, "text/", 5)) {
			unsigned char * const cs = getCharset(ct, lenCt);
			convertToUtf8((char**)&email->body, &email->lenBody, (char*)cs);
			if (cs != NULL) free(cs);

			if (lenCt >= 9 && memeq_anycase(ct + 5, "html", 4))
				htmlToText((char*)email->body, &email->lenBody);
			else
				cleanText(email->body, &email->lenBody, true);
		}
	}

	filterUtf8(email->body, email->lenBody, true);
}
