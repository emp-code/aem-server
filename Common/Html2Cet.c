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

#define AEM_TAGNAME_MAXLEN 11

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
	// Style tags
	AEM_HTML_TAG_hdr, // big, with a linebreak
	AEM_HTML_TAG_big,
	AEM_HTML_TAG_bld,
	AEM_HTML_TAG_ita,
	AEM_HTML_TAG_mno,
	AEM_HTML_TAG_sml,
	AEM_HTML_TAG_str,
	AEM_HTML_TAG_sub,
	AEM_HTML_TAG_sup,
	AEM_HTML_TAG_unl,
	// Layout tags
	AEM_HTML_TAG_lli,
	AEM_HTML_TAG_lol,
	AEM_HTML_TAG_lul,
	AEM_HTML_TAG_tbl,
	AEM_HTML_TAG_ttd,
	AEM_HTML_TAG_ttr,
	// Link tags
	AEM_HTML_TAG_a,
	AEM_HTML_TAG_audio,
	AEM_HTML_TAG_embed,
	AEM_HTML_TAG_frame,
	AEM_HTML_TAG_img,
	AEM_HTML_TAG_object,
	AEM_HTML_TAG_q,
	AEM_HTML_TAG_source,
	AEM_HTML_TAG_track,
	AEM_HTML_TAG_video
};

#define AEM_WANTATTR_NAME_MAXLEN 4
static int wantAttr(const enum aem_html_tag tag, const char * const name, const size_t lenName) {
	switch (tag) {
		case AEM_HTML_TAG_a:     return (lenName == 4 && memeq(name, "href", 4)) ? AEM_CET_CHAR_LNK : 0;
		case AEM_HTML_TAG_frame: return (lenName == 3 && memeq(name, "src",  3)) ? AEM_CET_CHAR_LNK : 0;
		case AEM_HTML_TAG_q:     return (lenName == 4 && memeq(name, "cite", 4)) ? AEM_CET_CHAR_LNK : 0;

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
		case AEM_HTML_TAG_q:  return '"';
		case AEM_HTML_TAG_br: return AEM_CET_CHAR_LBR;
		case AEM_HTML_TAG_hr: return AEM_CET_CHAR_HRL;
		case AEM_HTML_TAG_hdr:
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

static void addHrl(unsigned char * const src, size_t * const lenOut) {
	if (*lenOut == 0
	|| src[*lenOut - 1] == AEM_CET_CHAR_HRL
	|| (src[*lenOut - 1] >= AEM_CET_THRESHOLD_LAYOUT && src[*lenOut - 1] < 32)
	) return;

	if (src[*lenOut - 1] == ' ') (*lenOut)--;
	if (*lenOut > 0 && src[*lenOut - 1] == AEM_CET_CHAR_LBR) (*lenOut)--;
	if (*lenOut > 0 && src[*lenOut - 1] == AEM_CET_CHAR_LBR) (*lenOut)--;

	if (*lenOut > 1 && charInvisible(src + *lenOut - 2, 2)) {
		*lenOut -= 2;
	} else if (*lenOut > 2 && charInvisible(src + *lenOut - 3, 3)) {
		*lenOut -= 3;
	}

	src[*lenOut] = AEM_CET_CHAR_HRL;
	(*lenOut)++;
}

static void addLbr(unsigned char * const src, size_t * const lenOut, const bool oneIsEnough, const bool closing) {
	if (*lenOut == 0
	||  src[*lenOut - 1] == AEM_CET_CHAR_HRL
	|| (src[*lenOut - 1] >= AEM_CET_THRESHOLD_LAYOUT && src[*lenOut - 1] < 32)
	|| (src[*lenOut - 1] == AEM_CET_CHAR_LBR && (oneIsEnough || (*lenOut > 1 && src[*lenOut - 2] == AEM_CET_CHAR_LBR)))
	) return;

	if (!closing && src[*lenOut - 1] >= AEM_CET_THRESHOLD_MANUAL && src[*lenOut - 1] < 32) {
		(*lenOut)--;
		const unsigned char tmp = src[*lenOut];

		addLbr(src, lenOut, oneIsEnough, closing);

		src[*lenOut] = tmp;
		(*lenOut)++;
		return;
	}

	if (src[*lenOut - 1] == ' ') (*lenOut)--;

	if (*lenOut > 1 && charInvisible(src + *lenOut - 2, 2)) {
		*lenOut -= 2;
	} else if (*lenOut > 2 && charInvisible(src + *lenOut - 3, 3)) {
		*lenOut -= 3;
	}

	src[*lenOut] = AEM_CET_CHAR_LBR;
	(*lenOut)++;
}

static void addTagChar(unsigned char * const src, size_t * const lenOut, const enum aem_html_tag tag, const bool closing) {
	const unsigned char chr = tag2char(tag);
	if (chr == 0) return;

	if (chr >= AEM_CET_THRESHOLD_MANUAL && chr < 32) {
		static uint32_t tagsOpen = 0;

		if (chr == AEM_CET_CHAR_LLI && ((tagsOpen >> (31 - AEM_CET_CHAR_LOL)) & 1) == 0 && ((tagsOpen >> (31 - AEM_CET_CHAR_LUL)) & 1) == 0) {
			// List item without a list open - replace with linebreak
			addLbr(src, lenOut, false, closing);
			return;
		}

		if (tag == AEM_HTML_TAG_hdr && !closing) addLbr(src, lenOut, true, closing);

		if (((tagsOpen >> (31 - chr)) & 1) == 0 && !closing) {
			// We're opening a new tag

			if (chr == AEM_CET_CHAR_TBL) {
				if (*lenOut > 1 && *(src + *lenOut - 1) == AEM_CET_CHAR_LBR && *(src + *lenOut - 2) == AEM_CET_CHAR_LBR) (*lenOut)--;

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
				if (src[pos] > 32 || (src[pos] == 32 && chr >= AEM_CET_THRESHOLD_MANUAL && chr < AEM_CET_THRESHOLD_LAYOUT)) break; // Meaningful content found - proceed

				if (src[pos] == chr) {
					// We've arrived at the opening tag without finding meaningful content
					*lenOut = pos;
					if (chr == AEM_CET_CHAR_TBL || chr == AEM_CET_CHAR_LOL || chr == AEM_CET_CHAR_LUL || chr == AEM_CET_CHAR_LLI) addLbr(src, lenOut, false, closing);
					return;
				}
			}

			// Remove single-cell tables (the table char hasn't been added yet)
			if (chr == AEM_CET_CHAR_TBL) {
				int cellCount = 0;
				int columnCount = 0;
				int currentColumns = 0;

				ssize_t tableBegin = *lenOut - 3;
				for (;;tableBegin--) {
					if (tableBegin < 0) return;

					if (src[tableBegin] == AEM_CET_CHAR_TBL) break; // Beginning of table found

					if (src[tableBegin] == AEM_CET_CHAR_TTD) {
						// We encountered a table cell before the beginning of the table
						cellCount++;
						currentColumns++;
					} else if (src[tableBegin] == AEM_CET_CHAR_TTR) {
						if (currentColumns > columnCount) columnCount = currentColumns;
						currentColumns = 0;
					}
				}

				if (cellCount < 2) {
					memmove(src + tableBegin, src + tableBegin + 3, *lenOut - tableBegin - 5);
					*lenOut -= 5;

					addLbr(src, lenOut, false, closing);
					addLbr(src, lenOut, false, closing);
					return;
				} else if (columnCount < 3) {
					// Single-column table - replace rows with lines
					size_t newLenOut = tableBegin;

					for (size_t i = tableBegin + 1; i < *lenOut; i++) {
						if (src[i] == AEM_CET_CHAR_TTD) continue;
						if (src[i] == AEM_CET_CHAR_TTR) {
							if (newLenOut > 0 && src[newLenOut - 1] != AEM_CET_CHAR_LBR) {
								src[newLenOut] = AEM_CET_CHAR_LBR;
								newLenOut++;
							}
						} else {
							src[newLenOut] = src[i];
							newLenOut++;
						}
					}

					*lenOut = newLenOut;
					return;
				}
			} else if (chr < AEM_CET_THRESHOLD_LAYOUT) {
				// If there's space/linebreaks before this closing tag, place the closing tag first
				if (src[*lenOut - 1] == ' ') {
					src[*lenOut - 1] = chr;
					src[*lenOut] = ' ';
					(*lenOut)++;
					return;
				}

				if (*lenOut > 2 && src[*lenOut - 1] == AEM_CET_CHAR_LBR && src[*lenOut - 2] == AEM_CET_CHAR_LBR) {
					src[*lenOut - 2] = chr;
					src[*lenOut - 1] = AEM_CET_CHAR_LBR;
					src[*lenOut] = AEM_CET_CHAR_LBR;
					(*lenOut)++;
					return;
				}

				if (src[*lenOut - 1] == AEM_CET_CHAR_LBR) {
					src[*lenOut - 1] = chr;
					src[*lenOut] = AEM_CET_CHAR_LBR;
					(*lenOut)++;
					return;
				}
			}			
		} else return; // Invalid action: trying to open a tag that's already open, or to close a tag that isn't open
	} else if (chr == AEM_CET_CHAR_LBR) return addLbr(src, lenOut, false, closing);
	  else if (chr == AEM_CET_CHAR_HRL) return addHrl(src, lenOut);

	src[*lenOut] = chr;
	(*lenOut)++;

	if (tag == AEM_HTML_TAG_hdr && closing) addLbr(src, lenOut, true, closing);
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
			if (lenTagName == 7 && memeq(tagName + 1, "rticle", 6)) return AEM_HTML_TAG_br;
			if (lenTagName == 5 && memeq(tagName + 1, "side", 4)) return AEM_HTML_TAG_br;
		break;
		case 'b':
			if (lenTagName == 1) return AEM_HTML_TAG_bld; // b - bld
			if (lenTagName == 2 && tagName[1] == 'r') return AEM_HTML_TAG_br;
			if (lenTagName == 3 && tagName[1] == 'i' && tagName[2] == 'g') return AEM_HTML_TAG_big;
			if (lenTagName == 10 && memeq(tagName + 1, "lockquote", 9)) return AEM_HTML_TAG_br;
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
			if (lenTagName == 8 && memeq(tagName + 1, "ieldset", 7)) return AEM_HTML_TAG_br;
		break;
		case 'h':
			if (lenTagName == 2 && tagName[1] == 'r') return AEM_HTML_TAG_hr;
			if (lenTagName == 2 && tagName[1] >= '1' && tagName[1] <= '6') return AEM_HTML_TAG_hdr; // h1-h6 - hdr/big
			if (lenTagName == 6 && memeq(tagName + 1, "eader", 5)) return AEM_HTML_TAG_br;
		break;
		case 'i':
			if (lenTagName == 1) return AEM_HTML_TAG_ita; // i - ita
			if (lenTagName == 6 && memeq(tagName + 1, "frame", 5)) return AEM_HTML_TAG_frame;
			if (lenTagName == 3 && tagName[1] == 'm' && tagName[2] == 'g') return AEM_HTML_TAG_img;
		break;
		case 'k':
			if (lenTagName == 3 && tagName[1] == 'b' && tagName[2] == 'd') return AEM_HTML_TAG_mno; // kbd - mono
		break;
		case 'l':
			if (lenTagName == 2 && tagName[1] == 'i') return AEM_HTML_TAG_lli;
		break;
		case 'n':
			if (lenTagName == 3 && tagName[1] == 'a' && tagName[2] == 'v') return AEM_HTML_TAG_br;
		break;
		case 'o':
			if (lenTagName == 2 && tagName[1] == 'l') return AEM_HTML_TAG_lol;
			if (lenTagName == 6 && memeq(tagName + 1, "bject", 5)) return AEM_HTML_TAG_object;
		break;
		case 'p':
			if (lenTagName == 1) return AEM_HTML_TAG_br;
			if (lenTagName == 3 && tagName[1] == 'r' && tagName[2] == 'e') return AEM_HTML_TAG_mno; // pre - mono
		break;
		case 'q':
			if (lenTagName == 1) return AEM_HTML_TAG_q;
		break;
		case 's':
			if (lenTagName == 1) return AEM_HTML_TAG_str;
			if (lenTagName == 3 && tagName[1] == 'u' && tagName[2] == 'b') return AEM_HTML_TAG_sub;
			if (lenTagName == 3 && tagName[1] == 'u' && tagName[2] == 'p') return AEM_HTML_TAG_sup;
			if (lenTagName == 4 && memeq(tagName + 1, "amp",    3)) return AEM_HTML_TAG_mno; // samp
			if (lenTagName == 5 && memeq(tagName + 1, "mall",   4)) return AEM_HTML_TAG_sml; // small
			if (lenTagName == 6 && memeq(tagName + 1, "trike",  5)) return AEM_HTML_TAG_str; // strike
			if (lenTagName == 6 && memeq(tagName + 1, "trong",  5)) return AEM_HTML_TAG_bld; // strong
			if (lenTagName == 6 && memeq(tagName + 1, "ource",  5)) return AEM_HTML_TAG_source;
			if (lenTagName == 7 && memeq(tagName + 1, "ection", 6)) return AEM_HTML_TAG_br; // section
		break;
		case 't':
			if (lenTagName == 2 && tagName[1] == 'r') return AEM_HTML_TAG_ttr;
			if (lenTagName == 2 && (tagName[1] == 'd' || tagName[1] == 'h')) return AEM_HTML_TAG_ttd;
			if (lenTagName == 5 && memeq(tagName + 1, "able",    4)) return AEM_HTML_TAG_tbl;
			if (lenTagName == 5 && memeq(tagName + 1, "itle",    4)) return AEM_HTML_TAG_hdr; // title - hdr/big
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
	char tagName[AEM_TAGNAME_MAXLEN];

	enum aem_html_type type = AEM_HTML_TYPE_TX;
	int copyAttr = 0;
	bool isPre = false;

	for (size_t i = 0; i < *lenSrc; i++) {
		if ((type != AEM_HTML_TYPE_TX || !isPre) && src[i] == '\n') src[i] = ' ';

		switch (type) {
			case AEM_HTML_TYPE_T1: { // New tag's name
				if (src[i] == ' ') { // Tag name ends, has attributes
					tagType = getTagByName(tagName, lenTagName);
					type = AEM_HTML_TYPE_T2;

					if (lenTagName == 3 && memeq(tagName, "pre", 3)) isPre = true;
					else if (lenTagName == 4 && memeq(tagName, "/pre", 4)) isPre = false;
				} else if (src[i] == '>') { // Tag name ends, no attributes
					addTagChar(src, &lenOut, getTagByName(tagName, lenTagName), tagName[0] == '/');
					type = AEM_HTML_TYPE_TX;

					if (lenTagName == 3 && memeq(tagName, "pre", 3)) isPre = true;
					else if (lenTagName == 4 && memeq(tagName, "/pre", 4)) isPre = false;
				} else if (lenTagName < AEM_TAGNAME_MAXLEN) {
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
					copyAttr = 0;

					size_t offset = 0;
					while (src[i - offset - 1] == ' ') offset++;

					size_t lenAttrName = 0;
					for (size_t j = 1;; j++) {
						if (src[i - offset - j] == ' ' || src[i - offset - j] == '<' || !isalpha(src[i - offset - j])) break;
						lenAttrName++;

						if (lenAttrName > AEM_WANTATTR_NAME_MAXLEN) {
							lenAttrName = 0;
							break;
						}
					}

					if (lenAttrName > 0) {
						char attrName[lenAttrName];
						for (size_t j = 0; j < lenAttrName; j++) {
							attrName[j] = tolower(src[i - offset - lenAttrName + j]);
						}

						copyAttr = wantAttr(tagType, attrName, lenAttrName);
					}

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

				if (copyAttr == ' ') {
					for (int j = lenOut - 1; j >= 0; j--) {
						if (src[j] > 32) {
							src[lenOut] = ' ';
							lenOut++;
							break;
						} else if (src[j] == ' ' || src[j] == AEM_CET_CHAR_LBR || src[j] == AEM_CET_CHAR_HRL) break;
					}
				} else {
					if (lenOut > 0 && src[lenOut - 1] == ' ') {
						lenOut--;
					}

					src[lenOut] = copyAttr;
					lenOut++;
				}
			break;}

			case AEM_HTML_TYPE_QD:
			case AEM_HTML_TYPE_QS: {
				if (src[i] == (char)type) { // End of attribute -> add end marker
					if (copyAttr != 0 && (copyAttr != ' ' || (lenOut > 0 && src[lenOut - 1] != ' '))) {
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
					if (copyAttr != 0 && (copyAttr != ' ' || (lenOut > 0 && src[lenOut - 1] != ' '))) {
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
						const unsigned char * const styleEnd = memcasemem(src + i + 5, *lenSrc - (i + 5), (const unsigned char*)"</style", 7);
						if (styleEnd == NULL) {
							*lenSrc = lenOut;
							return;
						}

						i = styleEnd - src - 1;
						break;
					}

					if (memeq_anycase(src + i + 1, "!--", 3)) {
						const unsigned char * const cEnd = memcasemem(src + i + 2, *lenSrc - (i + 2), (const unsigned char*)"-->", 3);
						if (cEnd == NULL) {
							*lenSrc = lenOut;
							return;
						}

						i = cEnd - src + 2;
						break;
					}

					lenTagName = 0;
					tagName[0] = '-';
					type = AEM_HTML_TYPE_T1;
					break;
				} else if (src[i] == '\n' && isPre) {
					addTagChar(src, &lenOut, AEM_HTML_TAG_br, false);
				} else {
					i += addHtmlCharacter(src, *lenSrc, i, &lenOut) - 1;
				}
			break;}
		}
	}

	while (lenOut > 0 && src[lenOut - 1] == AEM_CET_CHAR_LBR) lenOut--;
	*lenSrc = lenOut;
}
