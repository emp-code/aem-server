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
[16B char*] AddressFrom (21c SixBit)
[16B char*] AddressTo (21c SixBit)

BodyBox format:
[2B uint16_t] Amount of padding used
[--- char*] Title
[1B char] Linebreak (\n)
[--- char*] Message body
*/
#define AEM_INTMSG_HEADERSIZE 37 // Note that HeadBox is a total (AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES) bytes

unsigned char *aem_intMsg_makeHeadBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const uint8_t senderMemberLevel, const char *adrFrom, const char *adrTo) {
	const uint32_t ts = (uint32_t)time(NULL);

	unsigned char plaintext[AEM_INTMSG_HEADERSIZE];
	memcpy(plaintext, &senderMemberLevel, 1);
	memcpy(plaintext + 1, &ts, 4);
	memcpy(plaintext + 5, adrFrom, 16);
	memcpy(plaintext + 21, adrTo, 16);

	unsigned char *ciphertext = malloc(AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES);
	sodium_memzero(ciphertext, AEM_INTMSG_HEADERSIZE + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, plaintext, AEM_INTMSG_HEADERSIZE, pk);

	return ciphertext;
}

unsigned char *aem_intMsg_makeBodyBox(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const char *bodyText, size_t *bodyLen) {
	const size_t bodyLenPadded = ceil(*bodyLen / (double)1024) * 1024;
	const size_t padLen = bodyLenPadded - *bodyLen;

	uint16_t padLen16 = padLen;

	unsigned char body[bodyLenPadded + 2];
	memcpy(body, &padLen16, 2);
	memcpy(body + 2, bodyText, *bodyLen);
	sodium_memzero(body + 2 + *bodyLen, padLen);

	*bodyLen = bodyLenPadded + 2;

	unsigned char *ciphertext = malloc(*bodyLen + crypto_box_SEALBYTES);
	sodium_memzero(ciphertext, *bodyLen + crypto_box_SEALBYTES);
	crypto_box_seal(ciphertext, body, *bodyLen, pk);

	return ciphertext;
}
