#ifndef AEM_MESSAGE_H
#define AEM_MESSAGE_H

#include <sodium.h>

#define AEM_HEADBOX_SIZE 41 // Encrypted: (AEM_HEADBOX_SIZE + crypto_box_SEALBYTES)

#define AEM_INFOBYTE_PROTOERR 8  // bit 3: protocol violation (commands out of order etc)
#define AEM_INFOBYTE_CMD_FAIL 16 // bit 4: invalid command
#define AEM_INFOBYTE_CMD_RARE 32 // bit 5: rare/unusual command (NOOP/RSET etc)
#define AEM_INFOBYTE_CMD_QUIT 64 // bit 6: QUIT issued
#define AEM_INFOBYTE_ESMTP 128   // bit 7: ESMTP

unsigned char *makeMsg_Int(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char *binFrom, const unsigned char *binTo, const char *bodyText, size_t * const bodyLen, const int senderLevel, const bool senderShield);
unsigned char *makeMsg_Ext(const unsigned char pk[crypto_box_PUBLICKEYBYTES], const unsigned char *binTo, const char *bodyText, size_t * const bodyLen,
	const uint32_t ip, const int32_t cs, const int16_t countryCode, const uint8_t attach, const uint8_t infoByte, const uint8_t spamByte);

#endif
