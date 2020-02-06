#ifndef AEM_DELIVERY_H
#define AEM_DELIVERY_H

void setAccessKey_account(const unsigned char * const newKey);
void setAccessKey_storage(const unsigned char * const newKey);

void deliverMessage(const char * const to, const size_t lenToTotal, const char * const from, const size_t lenFrom, const unsigned char * const msgBody, const size_t lenMsgBody, const struct sockaddr_in * const sockAddr, const int cs, const uint8_t tlsVersion, const unsigned char infoByte);

#endif
