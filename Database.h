#ifndef AEM_DATABASE_H
#define AEM_DATABASE_H

int getPublicKeyFromAddress(const char sixBit[16], unsigned char pk[32], const unsigned char hashKey[16]);

int addUserMessage(const unsigned char ownerPk[32], const unsigned char *msgData, const size_t msgLen);
unsigned char *getUserMessages(const unsigned char pk[32], size_t *msgLen);

#endif
