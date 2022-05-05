#include <stdlib.h>
#include <string.h>
#include <ctype.h> // for isupper/tolower
#include <sys/types.h> // for ssize_t

#include "../Global.h"
#include "memeq.h"
#include "HtmlRefs.h"
#include "Trim.h"

#include "HtmlToText.h"

enum aem_html_type {
	AEM_HTML_TYPE_TX = 0,
	AEM_HTML_TYPE_T1 = 1,
	AEM_HTML_TYPE_T2 = 2,
	AEM_HTML_TYPE_EQ = 3,
	AEM_HTML_TYPE_QN = ' ',
	AEM_HTML_TYPE_QD = '"',
	AEM_HTML_TYPE_QS = '\''
};

enum aem_html_tag {
	// Special use
	AEM_HTML_TAG_NULL,
	AEM_HTML_TAG_L1, // insert 1 linebreak
	AEM_HTML_TAG_L2, // insert 2 linebreaks
	// Opening tags
	AEM_HTML_TAG_a,
	AEM_HTML_TAG_audio,
	AEM_HTML_TAG_embed,
	AEM_HTML_TAG_frame,
	AEM_HTML_TAG_iframe,
	AEM_HTML_TAG_img,
	AEM_HTML_TAG_object,
	AEM_HTML_TAG_source,
	AEM_HTML_TAG_track,
	AEM_HTML_TAG_video,
};

static int wantAttr(const enum aem_html_tag tag, const char * const name, const size_t lenName) {
	switch (tag) {
		case AEM_HTML_TAG_a: return (lenName == 4 && memeq(name, "href", 4)) ? AEM_CET_CHAR_LNK : 0;

		case AEM_HTML_TAG_frame:
		case AEM_HTML_TAG_iframe: return (lenName == 3 && memeq(name, "src", 3)) ? AEM_CET_CHAR_LNK : 0;

		case AEM_HTML_TAG_audio:
		case AEM_HTML_TAG_embed:
		case AEM_HTML_TAG_img:
		case AEM_HTML_TAG_source:
		case AEM_HTML_TAG_track:
		case AEM_HTML_TAG_video: return (lenName == 3 && memeq(name, "src", 3)) ? AEM_CET_CHAR_FIL : 0;

		case AEM_HTML_TAG_object: return (lenName == 4 && memeq(name, "data", 4)) ? AEM_CET_CHAR_FIL : 0;
	}

	return 0;
}

static void addNewline(char * const out, size_t * const lenOut, const enum aem_html_tag tag) {
	if (tag == AEM_HTML_TAG_L1) {
		out[*lenOut] = '\n';
		(*lenOut)++;
	} else if (tag == AEM_HTML_TAG_L2) {
		out[*lenOut]     = '\n';
		out[*lenOut + 1] = '\n';
		*lenOut += 2;
	}
}

static enum aem_html_tag getTagByName(const char * const tagName, const size_t lenTagName) {
	if (lenTagName == 0) return AEM_HTML_TAG_NULL;

	if (lenTagName > 1 && tagName[0] == '/') {
		switch (tagName[1]) {
			case 'd':
				if (lenTagName == 4 && tagName[2] == 'i' && tagName[3] == 'v') return AEM_HTML_TAG_L1;
			break;
			case 'h':
				if (lenTagName == 3 && tagName[2] >= '1' && tagName[2] <= '6') return AEM_HTML_TAG_L1;
			break;
			case 'l':
				if (lenTagName == 3 && tagName[2] == 'i') return AEM_HTML_TAG_L1;
			break;
			case 'p':
				if (lenTagName == 2) return AEM_HTML_TAG_L1;
			break;
			case 't':
				if (lenTagName == 3 && (tagName[2] == 'd' || tagName[2] == 'r')) return AEM_HTML_TAG_L1;
				if (lenTagName == 6 && memeq(tagName + 2, "able", 4)) return AEM_HTML_TAG_L2;
				if (lenTagName == 6 && memeq(tagName + 2, "itle", 4)) return AEM_HTML_TAG_L2;
			break;
		}

		return AEM_HTML_TAG_NULL;
	}

	switch (tagName[0]) {
		case 'a':
			if (lenTagName == 1) return AEM_HTML_TAG_a;
			if (lenTagName == 5 && memeq(tagName + 1, "udio", 4)) return AEM_HTML_TAG_audio;
		break;
		case 'b':
			if (lenTagName == 2 && tagName[1] == 'r') return AEM_HTML_TAG_L1;
		break;
		case 'd':
			if (lenTagName == 3 && tagName[1] == 'i' && tagName[2] == 'v') return AEM_HTML_TAG_L1;
		break;
		case 'e':
			if (lenTagName == 5 && memeq(tagName + 1, "mbed", 4)) return AEM_HTML_TAG_embed;
		break;
		case 'f':
			if (lenTagName == 5 && memeq(tagName + 1, "rame", 4)) return AEM_HTML_TAG_frame;
		break;
		case 'h':
			if (lenTagName == 2 && tagName[1] >= '1' && tagName[1] <= '6') return AEM_HTML_TAG_L1;
			if (lenTagName == 2 && tagName[1] == 'r') return AEM_HTML_TAG_L1;
		break;
		case 'i':
			if (lenTagName == 6 && memeq(tagName + 1, "frame", 5)) return AEM_HTML_TAG_iframe;
			if (lenTagName == 3 && tagName[1] == 'm' && tagName[2] == 'g') return AEM_HTML_TAG_img;
		break;
		case 'l':
			if (lenTagName == 2 && tagName[1] == 'i') return AEM_HTML_TAG_L1;
		break;
		case 'o':
			if (lenTagName == 6 && memeq(tagName + 1, "bject", 5)) return AEM_HTML_TAG_object;
		break;
		case 'p':
			if (lenTagName == 1) return AEM_HTML_TAG_L1;
		break;
		case 's':
			if (lenTagName == 6 && memeq(tagName + 1, "ource", 5)) return AEM_HTML_TAG_source;
		break;
		case 't':
			if (lenTagName == 5 && memeq(tagName + 1, "able", 4)) return AEM_HTML_TAG_L2;
			if (lenTagName == 2 && (tagName[1] == 'd' || tagName[1] == 'r')) return AEM_HTML_TAG_L1;
			if (lenTagName == 5 && memeq(tagName + 1, "rack", 4)) return AEM_HTML_TAG_track;
			if (lenTagName == 5 && memeq(tagName + 1, "itle", 4)) return AEM_HTML_TAG_L2;
		break;
		case 'v':
			if (lenTagName == 5 && memeq(tagName + 1, "ideo", 4)) return AEM_HTML_TAG_video;
		break;
	}

	return AEM_HTML_TAG_NULL;
}

static void html2cet(char * const src, size_t * const lenSrc) {
	char * const out = malloc(*lenSrc);
	if (out == NULL) return;
	size_t lenOut = 0;

	enum aem_html_tag tagType = AEM_HTML_TAG_NULL;
	size_t lenTagName = 0;
	char tagName[8];

	enum aem_html_type type = AEM_HTML_TYPE_TX;
	int copyAttr = 0;

	for (size_t i = 0; i < *lenSrc; i++) {
		if (src[i] == '\n') src[i] = ' ';

		switch (type) {
			case AEM_HTML_TYPE_T1: { // New tag's name
				if (src[i] == ' ') { // Tag name ends, has attributes
					tagType = getTagByName(tagName, lenTagName);
					lenTagName = 0;
					type = AEM_HTML_TYPE_T2;
				} else if (src[i] == '>') { // Tag name ends, no attributes
					addNewline(out, &lenOut, getTagByName(tagName, lenTagName));
					lenTagName = 0;
					tagType = AEM_HTML_TAG_NULL;
					type = AEM_HTML_TYPE_TX;
				} else if (lenTagName < 7) {
					tagName[lenTagName] = tolower(src[i]);
					lenTagName++;
					break;
				} else { // Tag name too long, ignore
					tagName[0] = '-';
					break;
				}
			break;}

			case AEM_HTML_TYPE_T2: { // Inside of tag
				if (src[i] == '>') {
					addNewline(out, &lenOut, tagType);
					tagType = AEM_HTML_TAG_NULL;
					type = AEM_HTML_TYPE_TX;
				} else if (src[i] == '=') {
					size_t offset = 0;
					while (src[i - offset - 1] == ' ') offset++;

					if (!isalpha(src[i - offset - 1])) break; // Invalid attribute name, e.g. @=

					size_t lenAttrName = 0;
					for (size_t j = 1;; j++) {
						if (src[i - offset - j] == ' ') break;
						if (src[i - offset - j] == '<') {free(out); return;} // Should not happen

						lenAttrName++;
						if (lenAttrName > 9) break; // todo
					}

					char attrName[lenAttrName];
					for (size_t j = 0; j < lenAttrName; j++) {
						attrName[j] = tolower(src[i - offset - lenAttrName + j]);
					}

					copyAttr = wantAttr(tagType, attrName, lenAttrName);
					type = AEM_HTML_TYPE_EQ;
				} // else ignored
			break;}

			case AEM_HTML_TYPE_EQ: {
				if (src[i] == ' ') continue;

				if     (src[i] == '\'') type = AEM_HTML_TYPE_QS;
				else if (src[i] == '"') type = AEM_HTML_TYPE_QD;
				else {type = AEM_HTML_TYPE_QN; i--;}

				if (copyAttr == 0) break;

				if      (memeq_anycase(src + i + 1, "mailto:",  7)) {i += 7; copyAttr = ' ';}
				else if (memeq_anycase(src + i + 1, "tel:",     4)) {i += 4; copyAttr = ' ';}
				else if (memeq_anycase(src + i + 1, "http://",  7)) {i += 7;}
				else if (memeq_anycase(src + i + 1, "https://", 8)) {i += 8; copyAttr++;}
				else {copyAttr = 0; break;} // All others ignored/deleted

				out[lenOut] = copyAttr;
				lenOut++;
			break;}

			case AEM_HTML_TYPE_QN:
			case AEM_HTML_TYPE_QD:
			case AEM_HTML_TYPE_QS: {
				if (src[i] == (char)type) {
					if (copyAttr != 0) {
						out[lenOut] = copyAttr;
						lenOut++;

						if (copyAttr == AEM_CET_CHAR_FIL || copyAttr == (AEM_CET_CHAR_FIL + 1)) {
							out[lenOut] = '\n';
							lenOut++;
						}
					}

					type = AEM_HTML_TYPE_T2;
					continue;
				}

				if (copyAttr != 0) {
					out[lenOut] = src[i];
					lenOut++;
				}
			break;}

			case AEM_HTML_TYPE_TX: {
				if (src[i] == '<') {
					if (memeq_anycase(src + i + 1, "style", 5)) {
						const char * const styleEnd = (const char * const)memcasemem((unsigned char*)src + i + 5, *lenSrc - (i + 5), (unsigned char*)"</style", 7);

						if (styleEnd == NULL) {
							memcpy(src, out, lenOut);
							free(out);
							*lenSrc = lenOut;
							return;
						}

						i = styleEnd - src - 1;
						break;
					}

					if (memeq_anycase(src + i + 1, "!--", 3)) {
						const char * const cEnd = (const char * const)memcasemem((unsigned char*)src + i + 2, *lenSrc - (i + 2), (unsigned char*)"-->", 3);

						if (cEnd == NULL) {
							memcpy(src, out, lenOut);
							free(out);
							*lenSrc = lenOut;
							return;
						}

						i = cEnd - src + 2;
						break;
					}

					type = AEM_HTML_TYPE_T1;
					break;
				}

				out[lenOut] = src[i];
				lenOut++;
			break;}

			default:
				free(out);
				return;
		}
	}

	memcpy(src, out, lenOut);
	free(out);
	*lenSrc = lenOut;
}

void htmlToText(char * const text, size_t * const len) {
	removeControlChars((unsigned char*)text, len);
	html2cet(text, len);
	decodeHtmlRefs((unsigned char*)text, len);
	cleanText((unsigned char*)text, len, false);
}
