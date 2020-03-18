#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "../Global.h"

#include "Message.h"

/*
ExtMsg
	HeadBox
		[1B] InfoByte
			128: ExtMsg (on)
			 64: Protocol (ESMTP if set, SMTP if not set)
			 32: QUIT received
			 16: Unusual commands (NOOP/RSET/etc) received
			  8: Invalid commands received
			  4: Protocol violation (commands out of order, etc)
			  2:
			  1: Shield address
		[4B uint32_t] Timestamp
		[4B uint32_t] IP
		[2B uint16_t] TLS ciphersuite
		[1B uint8_t] TLS version
		[1B] SpamByte
		[2B char*] ISO 3166-1 alpha-2 country code
		[1B uint8_t] Number of attachements
		[4B] (unused)
		[15B char*] AddressTo (addr32)

	BodyBox:
		[-- char*] SMTP Greeting
		[1B char] Linebreak (\n)
		[-- char*] From address (envelope)
		[1B char] Linebreak (\n)
		[-- char*] Message data
		[2B uint16_t] Amount of padding

IntMsg
	HeadBox
		[1B uint8_t] InfoByte
			128: ExtMsg (off)
			 64:
			 32:
			 16:
			  8:
			  4:
			  2: Sender membership level (+2 if set)
			  1: Sender membership level (+1 if set)
		[4B uint32_t] Timestamp
		[15B char*] AddressFrom (addr32)
		[15B char*] AddressTo (addr32)

	BodyBox
		[2B uint16_t] Amount of padding
		[-- char*] Title
		[1B char] Linebreak (\n)
		[-- char*] Message body
*/

__attribute__((warn_unused_result))
static unsigned char *msg_makeBodyBox(const unsigned char * const pk, const unsigned char * const bodyText, size_t * const bodyLen) {
	const unsigned int setSize = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + *bodyLen + 2 + crypto_box_SEALBYTES;
	const uint16_t padLen = (setSize % 1024 == 0) ? 0 : 1024 - (setSize % 1024);
	const size_t bodyLenPadded = *bodyLen + padLen + 2;

	unsigned char body[bodyLenPadded];
	bzero(body, bodyLenPadded);
	memcpy(body, &padLen, 2);
	memcpy(body + 2, bodyText, *bodyLen);

	*bodyLen = bodyLenPadded;

	unsigned char * const ciphertext = malloc(*bodyLen + crypto_box_SEALBYTES);
	if (ciphertext == NULL) return NULL;
	crypto_box_seal(ciphertext, body, *bodyLen, pk);

	return ciphertext;
}

__attribute__((warn_unused_result))
static unsigned char *extMsg_makeHeadBox(const unsigned char * const pk, const unsigned char * const binTo, const uint32_t ip,
const int cs, const uint8_t tlsVersion, const int16_t countryCode, const unsigned char attach, unsigned char infoByte, const unsigned char spamByte) {
	const uint32_t ts = (uint32_t)time(NULL);
	const uint16_t cs16 = (cs > UINT16_MAX || cs < 0) ? 1 : cs;

	infoByte |= AEM_FLAG_MSGTYPE_EXTMSG;

	unsigned char plaintext[AEM_HEADBOX_SIZE];
	plaintext[0] = infoByte;
	memcpy(plaintext + 1, &ts, 4);
	memcpy(plaintext + 5, &ip, 4);
	memcpy(plaintext + 9, &cs16, 2);
	plaintext[11] = tlsVersion;
	plaintext[12] = spamByte;
	memcpy(plaintext + 13, &countryCode, 2);
	plaintext[15] = attach;
	bzero(plaintext + 16, 4); // 16-19 (4 bytes) unused
	memcpy(plaintext + 20, binTo, 15);

	unsigned char * const ciphertext = malloc(AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	if (ciphertext == NULL) return NULL;

	crypto_box_seal(ciphertext, plaintext, AEM_HEADBOX_SIZE, pk);
	return ciphertext;
}

__attribute__((warn_unused_result))
unsigned char *makeMsg_Ext(const unsigned char * const pk, const unsigned char * const binTo, const unsigned char * const bodyText, size_t * const bodyLen,
const uint32_t ip, const int cs, const uint8_t tlsVersion, const uint16_t countryCode, const uint8_t attach, const uint8_t infoByte, const uint8_t spamByte) {
	unsigned char * const headBox = extMsg_makeHeadBox(pk, binTo, ip, cs, tlsVersion, countryCode, attach, infoByte, spamByte);
	if (headBox == NULL) return NULL;

	unsigned char * const bodyBox = msg_makeBodyBox(pk, bodyText, bodyLen);
	if (bodyBox == NULL) {free(headBox); return NULL;}

	const size_t bsLen = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + *bodyLen + crypto_box_SEALBYTES;
	unsigned char * const boxSet = malloc(bsLen);
	if (boxSet == NULL) {free(headBox); free(bodyBox); return NULL;}

	memcpy(boxSet, headBox, AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	free(headBox);
	memcpy(boxSet + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES, bodyBox, *bodyLen + crypto_box_SEALBYTES);
	free(bodyBox);

	return boxSet;
}
