#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>

#include <sodium.h>

#include "../Common/Html2Cet.h"
#include "../Common/QuotedPrintable.h"
#include "../Common/ToUtf8.h"
#include "../Common/Trim.h"
#include "../Common/ValidUtf8.h"
#include "../Common/memeq.h"

#include "date.h"
#include "dkim.h"

#include "processing.h"

#define AEM_LIMIT_MULTIPARTS 50
#define AEM_DELIVER_MAXLEN_CHARSET 50

#define MTA_PROCESSING_CTE_NONE 0
#define MTA_PROCESSING_CTE_B64 1
#define MTA_PROCESSING_CTE_QP 2

static void processDkim(unsigned char * const src, size_t * const lenSrc, struct emailInfo * const email) {
	for (int i = 0; i < 7; i++) {
		const unsigned char * const headersEnd = memmem(src, *lenSrc, "\r\n\r\n", 4);
		if (headersEnd == NULL) break;

		unsigned char *start = memcasemem(src, headersEnd - src, "\nDKIM-Signature:", 16);
		if (start == NULL) break;
		start++;

		const int offset = verifyDkim(email, start, (src + *lenSrc) - start);
		if (offset == 0) break;

		// Delete the signature from the headers
		memmove(start, start + offset, (src + *lenSrc) - (start + offset));
		(*lenSrc) -= offset;
	}
	// Remove the CRLF added for DKIM
	(*lenSrc) -= 2;
	src[*lenSrc] = '\0';
}

// "abc" <def@ghj> --> abcAEM_CET_CHAR_SEPdef@ghj
static void minifyHeaderAddress(unsigned char *src, uint8_t * const lenSrc) {
	unsigned char *addrStart = memchr(src, '<', *lenSrc);
	unsigned char *addrEnd = memchr(src, '>', *lenSrc);
	if (addrStart == NULL || addrEnd == NULL || addrEnd < addrStart) return;
	addrStart++;
	const size_t lenAddr = addrEnd - addrStart;

	if (addrStart == src + 1) {
		memmove(src, addrStart, lenAddr);
		*lenSrc = lenAddr;
		return;
	}

	unsigned char *nameEnd = addrStart - 1;
	unsigned char *nameStart = src;
	while (isspace(*nameStart) && nameStart[1] != '<') nameStart++;

	const bool quot = (*nameStart == '"');
	if (quot) nameStart++;

	if (nameStart == nameEnd) {
		memmove(src, addrStart, lenAddr);
		*lenSrc = lenAddr;
		return;
	}

	size_t lenName = nameEnd - nameStart;
	while (lenName > 0 && isspace(nameStart[lenName - 1])) lenName--;

	if (quot && lenName > 0 && nameStart[lenName - 1] == '"') lenName--;

	if (lenName < 1) {
		memcpy(src, addrStart, lenAddr);
		*lenSrc = lenAddr;
		return;
	}

	unsigned char new[255];
	memcpy(new, nameStart, lenName);
	new[lenName] = AEM_CET_CHAR_SEP;
	memcpy(new + lenName + 1, addrStart, lenAddr);

	*lenSrc = lenName + 1 + lenAddr;
	memcpy(src, new, *lenSrc);
	return;
}

static void cleanHeaders(unsigned char * const data, size_t * const lenData) {
	size_t lenNew = 0;
	size_t lenKeep = 0;
	bool wasEw = false;
	int colonPos = -1;

	for (size_t i = 0; i < *lenData; i++) {
		if (i < *lenData - 1 && data[i] == '=' && data[i + 1] == '?') { // Encoded-Word; e.g. =?iso-8859-1?Q?=A1Hola,_se=F1or!?=
			if (wasEw && lenNew > 0) {
				// This is EW follows another: remove all spaces between the two
				while (lenNew > 0 && lenNew > lenKeep && data[lenNew - 1] == ' ') lenNew--;
			}

			const unsigned char * const charsetEnd = memchr(data + i + 2, '?', *lenData - (i + 2));
			const size_t lenCharset = (charsetEnd == NULL) ? 0 : charsetEnd - (data + i + 2);
			if (lenCharset < 1 || lenCharset > 30) break;

			char charset[lenCharset + 1];
			memcpy(charset, data + i + 2, lenCharset);
			charset[lenCharset] = '\0';

			if (data[i + 2 + lenCharset] != '?' || data[i + 4 + lenCharset] != '?') break;

			const bool isBase64 = (toupper(data[i + 3 + lenCharset]) == 'B');
			if (!isBase64 && toupper(data[i + 3 + lenCharset]) != 'Q') break;

			const unsigned char * const ewStart = data + i + 5 + lenCharset;
			const unsigned char * const ewEnd = memmem(ewStart, *lenData - (i + 5 + lenCharset), "?=", 2);
			if (ewEnd == NULL) {
				i += ewStart - (data + i) - 1;
				continue;
			}

			const size_t lenEw = ewEnd - ewStart;
			if (lenEw < 1) {
				i += ewEnd - (data + i) + 1;
				continue;
			}

			size_t lenDec = 0;
			unsigned char dec[lenEw + 1];

			if (isBase64) {
				if (sodium_base642bin(dec, lenEw, (char*)ewStart, lenEw, " \n", &lenDec, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) break;
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
					memcpy(data + lenNew, dec, lenDec);
					lenNew += lenDec;
				} else { // Decoded longer than original, not supported for now
					memset(data + lenNew, '?', lenOriginal);
					lenNew += lenOriginal;
				}
			} else {
				size_t lenDecUtf8 = 0;
				unsigned char *decUtf8 = (unsigned char*)toUtf8((char*)dec, lenDec, &lenDecUtf8, charset);

				if (decUtf8 != NULL && lenDecUtf8 > 0 && lenDecUtf8 <= lenOriginal) {
					filterUtf8(decUtf8, lenDecUtf8, false);
					memcpy(data + lenNew, decUtf8, lenDecUtf8);
					lenNew += lenDecUtf8;
				} else {
					memset(data + lenNew, '?', lenOriginal);
					lenNew += lenOriginal;
				}

				if (decUtf8 != NULL) free(decUtf8);
			}

			i += lenOriginal - 1;
			lenKeep = lenNew;
			wasEw = true;
			colonPos = 1;
		} else if (i < (*lenData - 1) && data[i] == '\n' && data[i + 1] == ' ') {
			continue; // Unfold the header by ignoring this linebreak before a space
		} else if (data[i] == '\n') {
			while (lenNew > 0 && data[lenNew - 1] == ' ') lenNew--;

			data[lenNew] = '\n';
			lenNew++;

			colonPos = -1;
		} else if (data[i] == ' ') {
			if (lenNew < 1 || (data[lenNew - 1] != ' ' && colonPos > 0)) {
				data[lenNew] = ' ';
				lenNew++;
			}
		} else if (colonPos < 0 && data[i] == ':') {
			while (i < (*lenData - 1) && (data[i + 1] == ' ')) i++; // Skip space after header-colon

			data[lenNew] = ':';
			lenNew++;

			colonPos = 0;
		} else if (data[i] > 32 && data[i] < 127) {
			data[lenNew] = data[i];
			lenNew++;

			wasEw = false;
			if (colonPos == 0) colonPos = 1;
		} // else skipped
	}

	*lenData = lenNew;
}

static int getHeaders(unsigned char * const src, size_t * const lenSrc, struct emailInfo * const email) {
	if (src == NULL || *lenSrc < 1) return -1;

	unsigned char *hend = memmem(src, *lenSrc, "\n\n", 2);
	if (hend == NULL) return -1;

	email->lenHead = hend - src;
	if (email->lenHead < 5) {email->lenHead = 0; return -1;}

	email->head = malloc(email->lenHead + 1);
	if (email->head == NULL) {syslog(LOG_ERR, "Failed allocation"); email->lenHead = 0; return -1;}
	memcpy(email->head, src, email->lenHead);
	email->head[email->lenHead] = '\0';

	memmove(src, hend + 1, (src + *lenSrc) - (hend + 1));
	*lenSrc -= (email->lenHead + 1);

	cleanHeaders(email->head, &email->lenHead);

	email->head[email->lenHead] = '\0';
	return 0;
}

static void moveHeader(unsigned char * const src, size_t * const lenSrc, const char * const needle, const size_t lenNeedle, unsigned char * const target, uint8_t * const lenTarget, const size_t limit) {
	unsigned char * const hdr = (unsigned char*)strcasestr((char*)src, needle);
	if (hdr == NULL) return;

	const unsigned char *hdrEnd = memchr(hdr + lenNeedle, '\n', (src + *lenSrc) - (hdr + lenNeedle));
	if (hdrEnd == NULL) hdrEnd = src + *lenSrc;

	if (target != NULL && lenTarget != NULL) {
		const size_t lenTgt = hdrEnd - (hdr + lenNeedle);
		*lenTarget = (lenTgt > limit) ? limit : lenTgt;
		memcpy(target, hdr + lenNeedle, *lenTarget);
	}

	const size_t lenMove = (src + *lenSrc) - hdrEnd;
	if (lenMove > 0) memmove(hdr, hdrEnd, lenMove);

	*lenSrc -= (hdrEnd - hdr);
	src[*lenSrc] = '\0';
}

static int getCte(const unsigned char * const h, const size_t len) {
	if (h == NULL) return MTA_PROCESSING_CTE_NONE;

	const unsigned char *cte = memcasemem(h, len, "\nContent-Transfer-Encoding:", 27);
	if (cte == NULL) return MTA_PROCESSING_CTE_NONE;
	cte += 27;

	const size_t lenCte = len - (cte - h);
	if (lenCte >= 16 && memeq_anycase(cte, "Quoted-Printable", 16)) return MTA_PROCESSING_CTE_QP;
	if (lenCte >= 6 && memeq_anycase(cte, "Base64", 6)) return MTA_PROCESSING_CTE_B64;
	return MTA_PROCESSING_CTE_NONE;
}

static unsigned char *decodeCte(const unsigned char * const src, size_t * const lenSrc, const int cte, const bool isText) {
	unsigned char *new;

	switch (cte) {
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
			if (sodium_base642bin(new, *lenSrc, (char*)src, *lenSrc, " \n", &lenNew, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {free(new); return NULL;}
			if (isText) removeControlChars(new, &lenNew);
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
	if (src == NULL || *src == NULL || charset == NULL) return;

	size_t lenUtf8;
	char * const utf8 = toUtf8(*src, *lenSrc, &lenUtf8, charset);
	if (utf8 == NULL) return;
	removeControlChars((unsigned char*)utf8, &lenUtf8);

	free(*src);
	*src = utf8;
	*lenSrc = lenUtf8;
}

static void getCharset(char * const target, const unsigned char *ct, const size_t lenCt) {
	target[0] = '\0';

	const unsigned char *cs = memcasemem(ct, lenCt, "charset", 7);
	if (cs == NULL || ((ct + lenCt) - cs) < 10) return;
	cs += 7;
	if (isspace(*cs)) cs++;

	if (*cs != '=') return;
	cs++;
	if (isspace(*cs)) cs++;

	const unsigned char *csEnd;
	if (*cs == '"' || *cs == '\'') {
		csEnd = memchr(cs + 1, *cs, (ct + lenCt) - (cs + 1));
		if (csEnd == NULL) return;
		cs++;
	} else {
		csEnd = mempbrk(cs, (ct + lenCt) - cs, (unsigned char[]){';', ' ', '\n'}, 3);
		if (csEnd == NULL) csEnd = ct + lenCt;
	}

	const size_t lenCs = csEnd - cs;
	if (lenCs >= AEM_DELIVER_MAXLEN_CHARSET) return;

	memcpy(target, cs, lenCs);
	target[lenCs] = '\0';
}

static unsigned char* getBound(const unsigned char * const src, const size_t lenSrc, size_t * const lenBound) {
	const unsigned char *start = memcasemem(src, lenSrc, "boundary", 8);
	if (start == NULL) return NULL;
	start = memchr(start + 8, '=', (src + lenSrc) - (start + 8));
	if (start == NULL || ((src + lenSrc) - start) < 3) return NULL;
	start++;

	const unsigned char *end = NULL;
	if (*start == '"' || *start == '\'') {
		end = memchr(start + 1, *start, (src + lenSrc) - (start + 1));
		start++;
	} else {
		end = mempbrk(start, (src + lenSrc) - start, (unsigned char[]){';', ' ', '\n'}, 3);
	}

	*lenBound = 3 + ((end != NULL) ? end : src + lenSrc) - start;
	unsigned char *bound = malloc(*lenBound);
	if (bound == NULL) {syslog(LOG_ERR, "Failed allocation"); return NULL;}
	bound[0] = '\n';
	bound[1] = '-';
	bound[2] = '-';
	memcpy(bound + 3, start, *lenBound - 3);

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
		end = mempbrk(fn, (src + lenSrc) - fn, (const unsigned char[]){*(fn - 1), '\n', '\0'}, 3);
		if (end == NULL) return 1;
	} else {
		end = mempbrk(fn, (src + lenSrc) - fn, (const unsigned char[]){';', ' ', '\n', '\0'}, 4);
		if (end == NULL) return 1;
	}

	const size_t lenFn = end - fn;
	if (lenFn > 255) return 1;
	memcpy(target, fn, lenFn);
	return lenFn;
}

static unsigned char *decodeMp(const unsigned char * const src, size_t *lenOut, struct emailInfo * const email, unsigned char * const bound0, const size_t lenBound0) {
	const size_t lenSrc = *lenOut;

	unsigned char *out = NULL;
	*lenOut = 0;

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

		if (begin[0] == '-' && begin[1] == '-') {
			searchBegin = src;
			i++;
			continue;
		}

		const unsigned char *hend = memmem(begin, (src + lenSrc) - begin, (unsigned char[]){'\n','\n'}, 2);
		if (hend == NULL) break;
		hend++;

		size_t lenPartHeaders = hend - begin;
		if (lenPartHeaders > 9999) break;

		unsigned char partHeaders[lenPartHeaders];
		memcpy(partHeaders, begin, lenPartHeaders);
		cleanHeaders(partHeaders, &lenPartHeaders);

		const unsigned char *ct = memcasemem(partHeaders, lenPartHeaders, "Content-Type:", 13);
		if (ct != NULL) ct += 13;
		const size_t lenCt = (ct != NULL) ? ((partHeaders + lenPartHeaders) - ct) : 0;

		unsigned char fn[256];
		const size_t lenFn = getNameHeader(ct, lenCt, fn);

		const unsigned char *boundEnd = memmem(hend, (src + lenSrc) - hend, bound[i], lenBound[i]);
		if (boundEnd == NULL) break;

		size_t lenNew = boundEnd - hend;

		const bool isText = (lenCt >= 5 && memeq_anycase(ct, "text/", 5));
		const bool isHtml = (isText && lenCt >= 9 && memeq_anycase(ct + 5, "html", 4));
		const bool multip = (lenCt >= 9 && memeq_anycase(ct, "multipart", 9));

		if (multip) {
			bound[boundCount] = getBound(ct + 9, (partHeaders + lenPartHeaders) - (ct + 9), lenBound + boundCount);

			if (bound[boundCount] != NULL) {
				boundCount++;
				if (boundCount >= AEM_LIMIT_MULTIPARTS) break;
			}
		} else {
			const unsigned char cte = getCte(partHeaders, lenPartHeaders);
			unsigned char *new = decodeCte(hend, &lenNew, cte, isText);
			if (new == NULL) break;

			if (isText) {
				char cs[AEM_DELIVER_MAXLEN_CHARSET];
				getCharset(cs, ct, (partHeaders + lenPartHeaders) - ct);
				convertToUtf8((char**)&new, &lenNew, cs);

				if (isHtml)
					html2cet(new, &lenNew);
				else
					cleanText(new, &lenNew);

				if (out == NULL) {
					out = new;
					*lenOut = lenNew;
				} else {
					unsigned char * const out2 = malloc(*lenOut + lenNew + 1);
					if (out2 == NULL) {syslog(LOG_ERR, "Failed allocation"); break;}
					memcpy(out2, out, *lenOut);
					free(out);
					out = out2;

					out[*lenOut] = AEM_CET_CHAR_SEP;
					memcpy(out + *lenOut + 1, new, lenNew);
					free(new);
					*lenOut += lenNew + 1;
				}
			} else if (email->attachCount < AEM_MAXNUM_ATTACHMENTS) {
				const size_t lenAtt = 22 + lenFn + lenNew;
				if (lenAtt <= AEM_API_BOX_SIZE_MAX) {
					email->attachment[email->attachCount] = malloc(lenAtt);
					if (email->attachment[email->attachCount] != NULL) {
						// Bytes 0-4 reserved for InfoByte and timestamp
						email->attachment[email->attachCount][5] = (lenFn - 1);
						// 16 bytes reserved for MsgId
						memcpy(email->attachment[email->attachCount] + 22, fn, lenFn);
						memcpy(email->attachment[email->attachCount] + 22 + lenFn, new, lenNew);
						free(new);

						email->lenAttachment[email->attachCount] = lenAtt;
						(email->attachCount)++;
					} else {free(new); syslog(LOG_ERR, "Failed allocation");}
				} else free(new); // Attachment too large
			} else free(new); // Attachment limit reached
		}

		searchBegin = boundEnd;
	}

	for (int i = 0; i < boundCount; i++) free(bound[i]);
	return out;
}

void processEmail(unsigned char * const src, size_t * const lenSrc, struct emailInfo * const email) {
	processDkim(src, lenSrc, email);
	removeControlChars(src, lenSrc);
	if (getHeaders(src, lenSrc, email) != 0) return;

	moveHeader(email->head, &email->lenHead, "\nMIME-Version:", 14, NULL, NULL, 0);
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
	if (lenCt >= 9 && memeq_anycase(ct, "multipart", 9)) {
		// CTE in headers: ignored
		moveHeader(email->head, &email->lenHead, "\nContent-Transfer-Encoding:", 27, NULL, NULL, 0);

		size_t lenBound;
		unsigned char * const bound = getBound(ct + 9, lenCt - 9, &lenBound);

		if (bound != NULL) {
			email->lenBody = *lenSrc;
			email->body = decodeMp(src, &email->lenBody, email, bound, lenBound);
			// bound is free'd by decodeMp()

			if (email->body == NULL) { // Error - decodeMp() failed
				email->body = src;
				email->lenBody = *lenSrc;
			}
		} else { // Error - getBound() failed
			email->body = src;
			email->lenBody = *lenSrc;
		}
	} else { // Single-part body
		unsigned char tmp[255];
		uint8_t lenTmp = 0;
		moveHeader(email->head, &email->lenHead, "\nContent-Transfer-Encoding:", 27, (unsigned char*)tmp, &lenTmp, 255);

		int cte;
		if (memcasemem(tmp, lenTmp, "quoted-printable", 16) != NULL) cte = MTA_PROCESSING_CTE_QP;
		else if (memcasemem(tmp, lenTmp, "base64", 6) != NULL) cte = MTA_PROCESSING_CTE_B64;
		else cte = 0;

		email->body = decodeCte(src, lenSrc, cte, true);
		if (email->body == NULL) email->body = src;
		email->lenBody = *lenSrc;

		if (lenCt < 2 || (lenCt >= 5 && memeq_anycase(ct, "text/", 5))) {
			char cs[AEM_DELIVER_MAXLEN_CHARSET];
			getCharset(cs, ct, lenCt);
			convertToUtf8((char**)&email->body, &email->lenBody, cs);

			if (lenCt >= 9 && memeq_anycase(ct + 5, "html", 4))
				html2cet(email->body, &email->lenBody);
			else
				cleanText(email->body, &email->lenBody);
		}
	}

	filterUtf8(email->body, email->lenBody, true);
}
