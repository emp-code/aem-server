#ifndef AEM_MESSAGE_H
#define AEM_MESSAGE_H

#include <sodium.h>

unsigned char *makeMsg_Int(const unsigned char * const pk, const unsigned char * const binFrom, const unsigned char * const binTo, const unsigned char * const bodyText, size_t * const bodyLen, const int senderLevel);
unsigned char *makeMsg_Ext(const unsigned char * const pk, const unsigned char * const binTo, const unsigned char * const bodyText, size_t * const bodyLen,
	const uint32_t ip, const int32_t cs, const uint8_t tlsVersion, const uint16_t countryCode, const uint8_t attach, const uint8_t infoByte, const uint8_t spamByte);

#endif
