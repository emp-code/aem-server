#ifndef AEM_MESSAGE_H
#define AEM_MESSAGE_H

#include <sodium.h>

#define AEM_HEADBOX_SIZE 35 // Encrypted: (AEM_HEADBOX_SIZE + crypto_box_SEALBYTES)

#define AEM_FLAG_MSGTYPE_INTMSG   0
#define AEM_FLAG_MSGTYPE_EXTMSG   1
#define AEM_FLAG_MSGTYPE_TEXTNOTE 2
#define AEM_FLAG_MSGTYPE_FILENOTE 3

unsigned char *makeMsg_Int(const unsigned char * const pk, const unsigned char * const binFrom, const unsigned char * const binTo, const unsigned char * const bodyText, size_t * const bodyLen, const int senderLevel);
unsigned char *makeMsg_Ext(const unsigned char * const pk, const unsigned char * const binTo, const unsigned char * const bodyText, size_t * const bodyLen,
	const uint32_t ip, const int32_t cs, const uint8_t tlsVersion, const int16_t countryCode, const uint8_t attach, const uint8_t infoByte, const uint8_t spamByte);

#endif
