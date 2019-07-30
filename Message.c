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
			2:
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
			2:
			3:
			4:
			5:
			6:
			7:
		[4B uint32_t] Timestamp
		[4B uint32_t] IP
		[4B int32_t] Ciphersuite
		[10B] (unused)
		[18B char*] AddressTo (24c SixBit)

	BodyBox:
		[2B uint16_t] Amount of padding
		[-- char*] Message data

TextNote
	HeadBox
		[1B uint8_t] InfoByte
			0: Message type (0)
			1: Message type (1)
			2:
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

static unsigned char *msg_makeBodyBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const char *bodyText, size_t *bodyLen) {
	const size_t bodyLenPadded = ceil(*bodyLen / (double)1024) * 1024;
	const size_t padLen = bodyLenPadded - *bodyLen;

	uint16_t padLen16 = padLen;

	unsigned char body[bodyLenPadded + 2];
	memcpy(body, &padLen16, 2);
	memcpy(body + 2, bodyText, *bodyLen);
	sodium_memzero(body + 2 + *bodyLen, padLen);

	*bodyLen = bodyLenPadded + 2;

	unsigned char *ciphertext = malloc(*bodyLen + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, body, *bodyLen, pk);

	return ciphertext;
}

static unsigned char *intMsg_makeHeadBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char adrFrom[18], const unsigned char adrTo[18], const int senderLevel, const bool senderShield) {
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

	unsigned char *ciphertext = malloc(AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, plaintext, AEM_HEADBOX_SIZE, pk);
	return ciphertext;
}

unsigned char *makeMsg_Int(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char *binFrom, const unsigned char *binTo, const char *bodyText, size_t * const bodyLen, const int senderLevel, const bool senderShield) {
	unsigned char *headBox = intMsg_makeHeadBox(pk, binFrom, binTo, senderLevel, senderShield);
	if (headBox == NULL) return NULL;

	unsigned char *bodyBox = msg_makeBodyBox(pk, bodyText, bodyLen);
	if (bodyBox == NULL) {free(headBox); return NULL;}

	const size_t bsLen = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + *bodyLen + crypto_box_SEALBYTES;
	unsigned char *boxSet = malloc(bsLen);
	if (boxSet == NULL) {free(headBox); free(bodyBox); return NULL;}

	memcpy(boxSet, headBox, AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	free(headBox);
	memcpy(boxSet + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES, bodyBox, *bodyLen + crypto_box_SEALBYTES);
	free(bodyBox);

	return boxSet;
}

static unsigned char *extMsg_makeHeadBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char *binTo, const uint32_t ip, const int32_t cs) {
	const uint32_t ts = (uint32_t)time(NULL);

	unsigned char infoByte = 0;
	BIT_SET(infoByte, 0);

	unsigned char plaintext[AEM_HEADBOX_SIZE];
	plaintext[0] = infoByte;
	memcpy(plaintext + 1, &ts, 4);
	memcpy(plaintext + 5, &ip, 4);
	memcpy(plaintext + 9, &cs, 4);
	// 10 bytes unused
	memcpy(plaintext + 23, binTo, 18);

	unsigned char *ciphertext = malloc(AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, plaintext, AEM_HEADBOX_SIZE, pk);

	return ciphertext;
}

unsigned char *makeMsg_Ext(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char *binTo, const uint32_t ip, const int32_t cs, const char *bodyText, size_t * const bodyLen) {
	unsigned char *headBox = extMsg_makeHeadBox(pk, binTo, ip, cs);
	if (headBox == NULL) return NULL;

	unsigned char *bodyBox = msg_makeBodyBox(pk, bodyText, bodyLen);
	if (bodyBox == NULL) {free(headBox); return NULL;}

	const size_t bsLen = AEM_HEADBOX_SIZE + crypto_box_SEALBYTES + *bodyLen + crypto_box_SEALBYTES;
	unsigned char *boxSet = malloc(bsLen);
	if (boxSet == NULL) {free(headBox); free(bodyBox); return NULL;}

	memcpy(boxSet, headBox, AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	free(headBox);
	memcpy(boxSet + AEM_HEADBOX_SIZE + crypto_box_SEALBYTES, bodyBox, *bodyLen + crypto_box_SEALBYTES);
	free(bodyBox);

	return boxSet;
}
