#ifndef AEM_DATABASE_H
#define AEM_DATABASE_H

#define AEM_NOTEDATA_LEN 5122 // 5 KiB + 2 bytes (16 bits) for length
#define AEM_ADMINDATA_LEN 9216 // 9 KiB

int addAccount(const unsigned char pk[crypto_box_PUBLICKEYBYTES]);

int64_t addressToHash(const unsigned char addr[18], const unsigned char hashKey[16]);

int getPublicKeyFromAddress(const unsigned char addr[18], unsigned char pk[32], const unsigned char hashKey[16], int *memberLevel);
int getUserInfo(const unsigned char pk[crypto_box_PUBLICKEYBYTES], uint8_t * const level, unsigned char ** const noteData, unsigned char ** const addrData, uint16_t * const lenAddr, unsigned char ** const gkData, uint16_t * const lenGk);
int getAdminData(unsigned char ** const adminData);
unsigned char *getUserMessages(const unsigned char pk[crypto_box_PUBLICKEYBYTES], uint8_t * const msgCount, const size_t maxSize);

int addUserMessage(const unsigned char ownerPk[32], const unsigned char *msgData, const size_t msgLen);

int deleteAddress(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const int64_t hash, const unsigned char *addrData, const size_t lenAddrData);
int updateAddress(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const unsigned char *addrData, const size_t lenAddrData);
int addAddress(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const int64_t hash);

int updateGatekeeper(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], char * const gkData, const size_t lenGkData, const unsigned char hashKey[16]);
int updateNoteData(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], const unsigned char *noteData);

int isUserAdmin(const unsigned char pk[crypto_box_PUBLICKEYBYTES]);

#endif
