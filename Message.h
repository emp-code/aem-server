#ifndef AEM_MESSAGE_H
#define AEM_MESSAGE_H

#include <sodium.h>

#define AEM_HEADBOX_SIZE 41 // Encrypted: (AEM_HEADBOX_SIZE + crypto_box_SEALBYTES)

#define AEM_INFOBYTE_PROTOERR 8  // bit 3: protocol violation (commands out of order etc)
#define AEM_INFOBYTE_CMD_FAIL 16 // bit 4: invalid command
#define AEM_INFOBYTE_CMD_RARE 32 // bit 5: rare/unusual command (NOOP/RSET etc)
#define AEM_INFOBYTE_CMD_QUIT 64 // bit 6: QUIT issued
#define AEM_INFOBYTE_ESMTP 128   // bit 7: ESMTP

unsigned char *makeMsg_Int(const unsigned char * const pk, const unsigned char * const binFrom, const unsigned char * const binTo, const char * const bodyText, size_t * const bodyLen, const int senderLevel);
unsigned char *makeMsg_Ext(const unsigned char * const pk, const unsigned char * const binTo, const char * const bodyText, size_t * const bodyLen,
	const uint32_t ip, const int32_t cs, const uint8_t tlsVersion, const int16_t countryCode, const uint8_t attach, const uint8_t infoByte, const uint8_t spamByte);

#endif
