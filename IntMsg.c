#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <sodium.h>

#include "IntMsg.h"

/* Internal Messages (IntMsg) consist of two Sealed Boxes (libsodium).
HeadBox is always created by the server. BodyBox may be made locally by the client.

HeadBox format:
[1B uint8_t] SenderMemberLevel
[4B uint32_t] Timestamp
[18B char*] AddressFrom (24c SixBit)
[18B char*] AddressTo (24c SixBit)

BodyBox format:
[2B uint16_t] Amount of padding used
[--- char*] Title
[1B char] Linebreak (\n)
[--- char*] Message body
*/

static unsigned char *aem_intMsg_makeHeadBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char senderInfo, const unsigned char adrFrom[18], const unsigned char adrTo[18]) {
	const uint32_t ts = (uint32_t)time(NULL);

	unsigned char plaintext[AEM_INTMSG_HEADERSIZE];
	plaintext[0] = senderInfo;
	memcpy(plaintext + 1, &ts, 4);
	memcpy(plaintext + 5, adrFrom, 18);
	memcpy(plaintext + 23, adrTo, 18);

	unsigned char *ciphertext = malloc(AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, plaintext, AEM_INTMSG_HEADERSIZE, pk);

	return ciphertext;
}

static unsigned char *aem_intMsg_makeBodyBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const char *bodyText, size_t *bodyLen) {
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

unsigned char *aem_intMsg_makeBoxSet(unsigned char *binFrom, unsigned char *binTo, unsigned char senderInfo, const char *bodyText, size_t *bodyLen, unsigned char pk[crypto_box_PUBLICKEYBYTES]) {
	unsigned char *headBox = aem_intMsg_makeHeadBox(pk, senderInfo, binFrom, binTo);
	if (headBox == NULL) return NULL;

	unsigned char *bodyBox = aem_intMsg_makeBodyBox(pk, bodyText, bodyLen);
	if (bodyBox == NULL) {free(headBox); return NULL;}

	const size_t bsLen = AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES + *bodyLen + crypto_box_SEALBYTES;
	unsigned char *boxSet = malloc(bsLen);
	if (boxSet == NULL) {free(headBox); free(bodyBox); return NULL;}

	memcpy(boxSet, headBox, AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES);
	free(headBox);
	memcpy(boxSet + AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES, bodyBox, *bodyLen + crypto_box_SEALBYTES);
	free(bodyBox);

	return boxSet;
}
