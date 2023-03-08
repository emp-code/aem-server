#include <ctype.h> // for isupper/tolower
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> // for ssize_t

#include "../Global.h"
#include "../Common/HtmlRefs.h"
#include "../Common/Trim.h"
#include "../Common/memeq.h"

#include "Html2Cet.h"

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
	AEM_HTML_TAG_br,
	AEM_HTML_TAG_hr,
	// Simple tags
	AEM_HTML_TAG_big,
	AEM_HTML_TAG_bld,
	AEM_HTML_TAG_hrl,
	AEM_HTML_TAG_img,
	AEM_HTML_TAG_ita,
	AEM_HTML_TAG_lli,
	AEM_HTML_TAG_lol,
	AEM_HTML_TAG_lul,
	AEM_HTML_TAG_mno,
	AEM_HTML_TAG_sml,
	AEM_HTML_TAG_str,
	AEM_HTML_TAG_sub,
	AEM_HTML_TAG_sup,
	AEM_HTML_TAG_tbl,
	AEM_HTML_TAG_ttd,
	AEM_HTML_TAG_ttr,
	AEM_HTML_TAG_unl,
	// Other tags
	AEM_HTML_TAG_a,
	AEM_HTML_TAG_audio,
	AEM_HTML_TAG_embed,
	AEM_HTML_TAG_frame,
	AEM_HTML_TAG_iframe,
	AEM_HTML_TAG_object,
	AEM_HTML_TAG_source,
	AEM_HTML_TAG_track,
	AEM_HTML_TAG_video
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

		default: return 0;
	}
}

static unsigned char tag2char(const enum aem_html_tag tag) {
	switch (tag) {
		case AEM_HTML_TAG_br: return AEM_CET_CHAR_LBR;
		case AEM_HTML_TAG_hr: return AEM_CET_CHAR_HRL;

		case AEM_HTML_TAG_big: return AEM_CET_CHAR_BIG;
		case AEM_HTML_TAG_bld: return AEM_CET_CHAR_BLD;
		case AEM_HTML_TAG_ita: return AEM_CET_CHAR_ITA;
		case AEM_HTML_TAG_lli: return AEM_CET_CHAR_LLI;
		case AEM_HTML_TAG_lol: return AEM_CET_CHAR_LOL;
		case AEM_HTML_TAG_lul: return AEM_CET_CHAR_LUL;
		case AEM_HTML_TAG_mno: return AEM_CET_CHAR_MNO;
		case AEM_HTML_TAG_sml: return AEM_CET_CHAR_SML;
		case AEM_HTML_TAG_str: return AEM_CET_CHAR_STR;
		case AEM_HTML_TAG_sub: return AEM_CET_CHAR_SUB;
		case AEM_HTML_TAG_sup: return AEM_CET_CHAR_SUP;
		case AEM_HTML_TAG_tbl: return AEM_CET_CHAR_TBL;
		case AEM_HTML_TAG_ttd: return AEM_CET_CHAR_TTD;
		case AEM_HTML_TAG_ttr: return AEM_CET_CHAR_TTR;
		case AEM_HTML_TAG_unl: return AEM_CET_CHAR_UNL;
		default: return 0;
	}
}

static void addLbr(unsigned char * const src, size_t * const lenOut) {
	if (
	   *lenOut == 0 // We don't want a linebreak as the first character
	|| (src[*lenOut - 1] > AEM_CET_THRESHOLD_LAYOUT && src[*lenOut - 1] < 32) // This linebreak follows a layout tag - skip
	|| (*lenOut > 1 && src[*lenOut - 1] == AEM_CET_CHAR_LBR && src[*lenOut - 2] == AEM_CET_CHAR_LBR) // Already have 2 consecutive linebreaks - don't add more
	) return;

	if (src[*lenOut - 1] == ' ') (*lenOut)--; // This linebreak follows a space - remove the space

	src[*lenOut] = AEM_CET_CHAR_LBR;
	(*lenOut)++;
}

static void addTagChar(unsigned char * const src, size_t * const lenOut, const enum aem_html_tag tag, const bool closing) {
	static uint32_t tagsOpen = 0;

	const unsigned char chr = tag2char(tag);
	if (chr == 0) return;

	if (chr >= AEM_CET_THRESHOLD_MANUAL) {
		if (chr == AEM_CET_CHAR_LLI && ((tagsOpen >> (31 - AEM_CET_CHAR_LOL)) & 1) == 0 && ((tagsOpen >> (31 - AEM_CET_CHAR_LUL)) & 1) == 0) {
			// List item without a list open - replace with linebreak
			addLbr(src, lenOut);
			return;
		}

		if (((tagsOpen >> (31 - chr)) & 1) == 0 && !closing) {
			// We're opening a new tag

			if (chr == AEM_CET_CHAR_TBL) {
				// Tables begin with <table> <tr> <td>
				memcpy(src + *lenOut, (unsigned char[]) {AEM_CET_CHAR_TBL, AEM_CET_CHAR_TTR, AEM_CET_CHAR_TTD}, 3);
				*lenOut += 3;
				tagsOpen |= (1 << (31 - AEM_CET_CHAR_TBL)) | (1 << (31 - AEM_CET_CHAR_TTR)) | (1 << (31 - AEM_CET_CHAR_TTD));
				return;
			} else if (chr == AEM_CET_CHAR_TTR) {
				if (((tagsOpen >> (31 - AEM_CET_CHAR_TBL)) & 1) == 0) return; // Forbid opening a <tr> without a <table> open

				// <tr>'s begin with <tr> <td>
				memcpy(src + *lenOut, (unsigned char[]) {AEM_CET_CHAR_TTR, AEM_CET_CHAR_TTD}, 2);
				*lenOut += 2;
				tagsOpen |= (1 << (31 - AEM_CET_CHAR_TTR)) | (1 << (31 - AEM_CET_CHAR_TTD));
				return;
			} else if (chr == AEM_CET_CHAR_TTD) {
				if (((tagsOpen >> (31 - AEM_CET_CHAR_TBL)) & 1) == 0) return; // Forbid opening a <td> without a <table> open

				if (((tagsOpen >> (31 - AEM_CET_CHAR_TTR)) & 1) == 0) {
					// Trying to open a <td> without a <tr> open - let's add the <tr> first
					src[*lenOut] = AEM_CET_CHAR_TTR;
					(*lenOut)++;
					tagsOpen |= (1 << (31 - AEM_CET_CHAR_TTR));
				}
			}

			tagsOpen |= (1 << (31 - chr));
		} else if (((tagsOpen >> (31 - chr)) & 1) == 1 && closing) {
			// We're closing a currently open tag

			// Remove space/linebreaks before layout tag end
			if (chr >= AEM_CET_THRESHOLD_LAYOUT) {
				while (src[*lenOut - 1] == ' ' || src[*lenOut - 1] == AEM_CET_CHAR_LBR) {
					(*lenOut)--;
				}
			}

			if (chr == AEM_CET_CHAR_TTR) {
				// Closing <tr> also means closing <td>, make sure that's done
				if (((tagsOpen >> (31 - AEM_CET_CHAR_TTD)) & 1) == 1) {
					addTagChar(src, lenOut, AEM_HTML_TAG_ttd, true);
				}
			} else if (chr == AEM_CET_CHAR_TBL) {
				if (((tagsOpen >> (31 - AEM_CET_CHAR_TTR)) & 1) == 1) {
					// We're closing a <table>, but haven't closed the <tr> yet, let's do that

					if (((tagsOpen >> (31 - AEM_CET_CHAR_TTD)) & 1) == 1) {
						// We haven't closed the <td> either, let's do that first
						addTagChar(src, lenOut, AEM_HTML_TAG_ttd, true);
					}

					addTagChar(src, lenOut, AEM_HTML_TAG_ttr, true);
				}
			}

			tagsOpen &= ~(1 << (31 - chr));

			// Find if there's meaningful content between this closing-tag and the opening-tag
			for (size_t pos = *lenOut - 1;; pos--) {
				if (src[pos] > 32) break; // Meaningful content found - proceed

				if (src[pos] == chr) {
					// We've arrived at the opening tag without finding meaningful content
					*lenOut = pos;
					if (chr >= AEM_CET_THRESHOLD_LAYOUT) addLbr(src, lenOut);
					return;
				}
			}

			// Remove single-cell tables (the table char hasn't been added yet)
			if (chr == AEM_CET_CHAR_TBL) {
				int cellCount = 0;
				size_t tableBegin = *lenOut - 3;
				for (;;tableBegin--) {
					if (src[tableBegin] == AEM_CET_CHAR_TBL) break; // Beginning of table found

					if (src[tableBegin] == AEM_CET_CHAR_TTD) {
						// We encountered a table cell before the beginning of the table
						cellCount++;
					}
				}

				if (cellCount < 2) {
					memmove(src + tableBegin, src + tableBegin + 3, *lenOut - tableBegin - 5);
					*lenOut -= 5;

					addLbr(src, lenOut);
					addLbr(src, lenOut);
					return;
				}
			}
		} else return; // Invalid action: trying to open a tag that's already open, or to close a tag that isn't open
	} else if (chr == AEM_CET_CHAR_LBR) return addLbr(src, lenOut);

	src[*lenOut] = chr;
	(*lenOut)++;
}

static enum aem_html_tag getTagByName(const char *tagName, size_t lenTagName) {
	if (lenTagName == 0) return AEM_HTML_TAG_NULL;
	if (tagName[0] == '/') {
		tagName++;
		lenTagName--;
	}

	if (tagName[lenTagName - 1] == '/') {
		if (lenTagName == 1) return AEM_HTML_TAG_NULL;
		lenTagName--;
	}

	switch (tagName[0]) {
		case 'a':
			if (lenTagName == 1) return AEM_HTML_TAG_a;
			if (lenTagName == 5 && memeq(tagName + 1, "udio", 4)) return AEM_HTML_TAG_audio;
		break;
		case 'b':
			if (lenTagName == 1) return AEM_HTML_TAG_bld; // b - bld
			if (lenTagName == 2 && tagName[1] == 'r') return AEM_HTML_TAG_br;
			if (lenTagName == 3 && tagName[1] == 'i' && tagName[2] == 'g') return AEM_HTML_TAG_big;
		break;
		case 'c':
			if (lenTagName == 4 && memeq(tagName + 1, "ode", 3)) return AEM_HTML_TAG_mno; // code - mono
		break;
		case 'd':
			if (lenTagName == 3 && tagName[1] == 'e' && tagName[2] == 'l') return AEM_HTML_TAG_str; // del - ita
			if (lenTagName == 3 && tagName[1] == 'i' && tagName[2] == 'v') return AEM_HTML_TAG_br;
		break;
		case 'e':
			if (lenTagName == 2 && tagName[1] == 'm') return AEM_HTML_TAG_ita; // em - ita
			if (lenTagName == 5 && memeq(tagName + 1, "mbed", 4)) return AEM_HTML_TAG_embed;
		break;
		case 'f':
			if (lenTagName == 5 && memeq(tagName + 1, "rame", 4)) return AEM_HTML_TAG_frame;
		break;
		case 'h':
			if (lenTagName == 2 && tagName[1] == 'r') return AEM_HTML_TAG_hrl;
			if (lenTagName == 2 && tagName[1] >= '1' && tagName[1] <= '6') return AEM_HTML_TAG_big; // h1-h6 - big
		break;
		case 'i':
			if (lenTagName == 1) return AEM_HTML_TAG_ita; // i - ita
			if (lenTagName == 6 && memeq(tagName + 1, "frame", 5)) return AEM_HTML_TAG_iframe;
			if (lenTagName == 3 && tagName[1] == 'm' && tagName[2] == 'g') return AEM_HTML_TAG_img;
		break;
		case 'k':
			if (lenTagName == 3 && tagName[1] == 'b' && tagName[2] == 'd') return AEM_HTML_TAG_mno; // kbd - mono
		break;
		case 'l':
			if (lenTagName == 2 && tagName[1] == 'i') return AEM_HTML_TAG_lli;
		break;
		case 'o':
			if (lenTagName == 2 && tagName[1] == 'l') return AEM_HTML_TAG_lol;
			if (lenTagName == 6 && memeq(tagName + 1, "bject", 5)) return AEM_HTML_TAG_object;
		break;
		case 'p':
			if (lenTagName == 1) return AEM_HTML_TAG_br;
			if (lenTagName == 3 && tagName[1] == 'r' && tagName[2] == 'e') return AEM_HTML_TAG_mno; // pre - mono
		break;
		case 's':
			if (lenTagName == 1) return AEM_HTML_TAG_str;
			if (lenTagName == 3 && tagName[1] == 'u' && tagName[2] == 'b') return AEM_HTML_TAG_sub;
			if (lenTagName == 3 && tagName[1] == 'u' && tagName[2] == 'p') return AEM_HTML_TAG_sup;
			if (lenTagName == 4 && memeq(tagName + 1, "amp",   3)) return AEM_HTML_TAG_mno; // samp
			if (lenTagName == 5 && memeq(tagName + 1, "mall",  4)) return AEM_HTML_TAG_sml; // small
			if (lenTagName == 6 && memeq(tagName + 1, "trike", 5)) return AEM_HTML_TAG_str; // strike
			if (lenTagName == 6 && memeq(tagName + 1, "trong", 5)) return AEM_HTML_TAG_bld; // strong
			if (lenTagName == 6 && memeq(tagName + 1, "ource", 5)) return AEM_HTML_TAG_source;
		break;
		case 't':
			if (lenTagName == 2 && tagName[1] == 'r') return AEM_HTML_TAG_ttr;
			if (lenTagName == 2 && (tagName[1] == 'd' || tagName[1] == 'h')) return AEM_HTML_TAG_ttd;
			if (lenTagName == 5 && memeq(tagName + 1, "able",    4)) return AEM_HTML_TAG_tbl;
			if (lenTagName == 5 && memeq(tagName + 1, "rack",    4)) return AEM_HTML_TAG_track;
			if (lenTagName == 8 && memeq(tagName + 1, "extarea", 7)) return AEM_HTML_TAG_mno; // textarea - mono
		break;
		case 'u':
			if (lenTagName == 1) return AEM_HTML_TAG_unl; // u - unl
			if (lenTagName == 2 && tagName[1] == 'l') return AEM_HTML_TAG_lul;
		break;
		case 'v':
			if (lenTagName == 5 && memeq(tagName + 1, "ideo", 4)) return AEM_HTML_TAG_video;
			if (lenTagName == 3 && tagName[1] == 'a' && tagName[2] == 'r') return AEM_HTML_TAG_ita; // var - ita
		break;
	}

	return AEM_HTML_TAG_NULL;
}

void html2cet(unsigned char * const src, size_t * const lenSrc) {
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
					addTagChar(src, &lenOut, getTagByName(tagName, lenTagName), tagName[0] == '/');
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
					addTagChar(src, &lenOut, tagType, tagName[0] == '/');
					type = AEM_HTML_TYPE_TX;
				} else if (src[i] == '=') {
					size_t offset = 0;
					while (src[i - offset - 1] == ' ') offset++;

					if (!isalpha(src[i - offset - 1])) break; // Invalid attribute name, e.g. @=

					size_t lenAttrName = 0;
					for (size_t j = 1;; j++) {
						if (src[i - offset - j] == ' ') break;
						if (src[i - offset - j] == '<') return; // Should not happen

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

				src[lenOut] = copyAttr;
				lenOut++;
			break;}

			case AEM_HTML_TYPE_QD:
			case AEM_HTML_TYPE_QS: {
				if (src[i] == (char)type) { // End of attribute -> add end marker
					if (copyAttr != 0) {
						src[lenOut] = copyAttr;
						lenOut++;
					}

					type = AEM_HTML_TYPE_T2;
				} else if (copyAttr != 0) { // Attribute value -> copy
					i += addHtmlCharacter(src, *lenSrc, i, &lenOut) - 1;
				}
			break;}

			case AEM_HTML_TYPE_QN: {
				if (src[i] == ' ' || src[i] == '>') { // End of attribute -> add end marker
					if (copyAttr != 0) {
						src[lenOut] = copyAttr;
						lenOut++;
					}

					i--;
					type = AEM_HTML_TYPE_T2;
				} else if (copyAttr != 0) { // Attribute value -> copy
					i += addHtmlCharacter(src, *lenSrc, i, &lenOut) - 1;
				}
			break;}

			case AEM_HTML_TYPE_TX: {
				if (src[i] == '<') {
					if (memeq_anycase(src + i + 1, "style", 5)) {
						const unsigned char * const styleEnd = memcasemem(src + i + 5, *lenSrc - (i + 5), (unsigned char*)"</style", 7);
						if (styleEnd == NULL) return;
						i = styleEnd - src - 1;
						break;
					}

					if (memeq_anycase(src + i + 1, "!--", 3)) {
						const unsigned char * const cEnd = memcasemem(src + i + 2, *lenSrc - (i + 2), (unsigned char*)"-->", 3);
						if (cEnd == NULL) return;
						i = cEnd - src + 2;
						break;
					}

					lenTagName = 0;
					type = AEM_HTML_TYPE_T1;
					break;
				}

				i += addHtmlCharacter(src, *lenSrc, i, &lenOut) - 1;
			break;}
		}
	}

	*lenSrc = lenOut;
}
