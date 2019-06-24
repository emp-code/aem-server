#ifndef AEM_DATABASE_H
#define AEM_DATABASE_H

int64_t addressToHash(const unsigned char addr[18], const unsigned char hashKey[16]);

int getPublicKeyFromAddress(const unsigned char addr[18], unsigned char pk[32], const unsigned char hashKey[16], int *memberLevel);
unsigned char *getUserInfo(const unsigned char pk[32], uint8_t *level, uint16_t *addrDataSize);
unsigned char *getUserMessages(const unsigned char pk[32], int *msgCount, const size_t maxSize);

int addUserMessage(const unsigned char ownerPk[32], const unsigned char *msgData, const size_t msgLen);

int deleteAddress(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const int64_t hash, const unsigned char *addrData, const size_t lenAddrData);
int updateAddress(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const unsigned char *addrData, const size_t lenAddrData);
int addAddress(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const int64_t hash);

int updateGatekeeper(const int64_t upk64, char * const gkData, const size_t lenGkData, const unsigned char hashKey[16]);

#endif
