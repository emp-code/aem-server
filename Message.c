#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <math.h> // for ceil

#include <sodium.h>

#include "Message.h"

#define BIT_SET(a,b) ((a) |= (1ULL<<(b)))

/*
IntMsg
	HeadBox
		[1B uint8_t] InfoByte
			0: Message type (0)
			1: Message type (0)
			2: (Reserved) (0)
			3:
			4: Sender membership level (+1 if set)
			5: Sender membership level (+2 if set)
			6:
			7: Address type (Shield if set, normal if not set)
		[4B uint32_t] Timestamp
		[18B char*] AddressFrom (24c SixBit)
		[18B char*] AddressTo (24c SixBit)

	BodyBox
		[2B uint16_t] Amount of padding
		[-- char*] Title
		[1B char] Linebreak (\n)
		[-- char*] Message body

ExtMsg
	HeadBox
		[1B] InfoByte
			0: Message type (1)
			1: Message type (0)
			2: (Reserved) (0)
			3: Protocol violation (commands out of order, etc)
			4: Invalid commands received
			5: Unusual commands (NOOP/RSET/etc) received
			6: QUIT received
			7: Protocol (ESMTP if set, SMTP if not set)
		[4B uint32_t] Timestamp
		[4B uint32_t] IP
		[4B int32_t] TLS ciphersuite
		[1B uint8_t] TLS version
		[5B] (unused)
		[2B char*] ISO 3166-1 alpha-2 country code
		[1B uint8_t] Number of attachements
		[1B] SpamByte
		[18B char*] AddressTo (24c SixBit)

	BodyBox:
		[2B uint16_t] Amount of padding
		[-- char*] SMTP Greeting
		[1B char] Linebreak (\n)
		[-- char*] From address (envelope)
		[1B char] Linebreak (\n)
		[-- char*] Message data

TextNote
	HeadBox
		[1B uint8_t] InfoByte
			0: Message type (0)
			1: Message type (1)
			2: (Reserved) (0)
			3:
			4:
			5:
			6:
			7:
		[4B uint32_t] Timestamp
		[36B] (unused)

	BodyBox
		[2B uint16_t] Amount of padding
		[-- char*] Message data
*/

static unsigned char *msg_makeBodyBox(const unsigned char * const pk, const char * const bodyText, size_t * const bodyLen) {
	const size_t bodyLenPadded = ceil(*bodyLen / (double)1024) * 1024;
	const size_t padLen = bodyLenPadded - *bodyLen;

	const uint16_t padLen16 = padLen;

	unsigned char body[bodyLenPadded + 2];
	memcpy(body, &padLen16, 2);
	memcpy(body + 2, bodyText, *bodyLen);
	sodium_memzero(body + 2 + *bodyLen, padLen);

	*bodyLen = bodyLenPadded + 2;

	unsigned char * const ciphertext = malloc(*bodyLen + crypto_box_SEALBYTES);
	if (ciphertext == NULL) return NULL;

	crypto_box_seal(ciphertext, body, *bodyLen, pk);
	return ciphertext;
}

static unsigned char *intMsg_makeHeadBox(const unsigned char * const pk, const unsigned char * const adrFrom, const unsigned char * const adrTo, const int senderLevel, const bool senderShield) {
	const uint32_t ts = (uint32_t)time(NULL);

	unsigned char infoByte = 0;

	switch(senderLevel) {
		case 3:
			BIT_SET(infoByte, 4);
			BIT_SET(infoByte, 5);
			break;
		case 2:
			BIT_SET(infoByte, 5);
			break;
		case 1:
			BIT_SET(infoByte, 4);
			break;
	}

	if (senderShield) BIT_SET(infoByte, 7);

	unsigned char plaintext[AEM_HEADBOX_SIZE];
	plaintext[0] = infoByte;
	memcpy(plaintext + 1, &ts, 4);
	memcpy(plaintext + 5, adrFrom, 18);
	memcpy(plaintext + 23, adrTo, 18);

	unsigned char * const ciphertext = malloc(AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	if (ciphertext == NULL) return NULL;

	crypto_box_seal(ciphertext, plaintext, AEM_HEADBOX_SIZE, pk);
	return ciphertext;
}

unsigned char *makeMsg_Int(const unsigned char * const pk, const unsigned char * const binFrom, const unsigned char * const binTo, const char * const bodyText, size_t * const bodyLen, const int senderLevel, const bool senderShield) {
	unsigned char * const headBox = intMsg_makeHeadBox(pk, binFrom, binTo, senderLevel, senderShield);
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

static unsigned char *extMsg_makeHeadBox(const unsigned char * const pk, const unsigned char * const binTo, const uint32_t ip,
const int32_t cs, const uint8_t tlsVersion, const int16_t countryCode, const unsigned char attach, unsigned char infoByte, const unsigned char spamByte) {
	const uint32_t ts = (uint32_t)time(NULL);

	BIT_SET(infoByte, 0);

	unsigned char plaintext[AEM_HEADBOX_SIZE];
	plaintext[0] = infoByte;
	memcpy(plaintext + 1, &ts, 4);
	memcpy(plaintext + 5, &ip, 4);
	memcpy(plaintext + 9, &cs, 4);
	plaintext[13] = tlsVersion;
	bzero(plaintext + 14, 5); // 14-18 (5 bytes) unused
	memcpy(plaintext + 19, &countryCode, 2);
	plaintext[21] = attach;
	plaintext[22] = spamByte;
	memcpy(plaintext + 23, binTo, 18);

	unsigned char * const ciphertext = malloc(AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	if (ciphertext == NULL) return NULL;

	crypto_box_seal(ciphertext, plaintext, AEM_HEADBOX_SIZE, pk);
	return ciphertext;
}

unsigned char *makeMsg_Ext(const unsigned char * const pk, const unsigned char * const binTo, const char * const bodyText, size_t * const bodyLen,
const uint32_t ip, const int32_t cs, const uint8_t tlsVersion, const int16_t countryCode, const uint8_t attach, const uint8_t infoByte, const uint8_t spamByte) {
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
