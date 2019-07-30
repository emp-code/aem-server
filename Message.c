#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h> // for ceil

#include <sodium.h>

#include "Message.h"

/*
IntMsg
	HeadBox
	[1B uint8_t] SenderMemberLevel
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
	[18B char*] AddressTo (24c SixBit)
	[4B uint32_t] Timestamp
	[4B uint32_t] IP
	[4B int32_t] Ciphersuite
	[11B] (unused)

	BodyBox:
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

static unsigned char *intMsg_makeHeadBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char senderInfo, const unsigned char adrFrom[18], const unsigned char adrTo[18]) {
	const uint32_t ts = (uint32_t)time(NULL);

	unsigned char plaintext[AEM_HEADBOX_SIZE];
	plaintext[0] = senderInfo;
	memcpy(plaintext + 1, &ts, 4);
	memcpy(plaintext + 5, adrFrom, 18);
	memcpy(plaintext + 23, adrTo, 18);

	unsigned char *ciphertext = malloc(AEM_HEADBOX_SIZE + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, plaintext, AEM_HEADBOX_SIZE, pk);
	return ciphertext;
}

unsigned char *makeMsg_Int(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char *binFrom, const unsigned char *binTo, const unsigned char senderInfo, const char *bodyText, size_t * const bodyLen) {
	unsigned char *headBox = intMsg_makeHeadBox(pk, senderInfo, binFrom, binTo);
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

	unsigned char plaintext[AEM_HEADBOX_SIZE];
	memcpy(plaintext, binTo, 18);
	memcpy(plaintext + 18, &ts, 4);
	memcpy(plaintext + 22, &ip, 4);
	memcpy(plaintext + 26, &cs, 4);
	// 11 bytes unused

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
