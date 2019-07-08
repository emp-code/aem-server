#ifndef AEM_DATABASE_H
#define AEM_DATABASE_H

#define AEM_NOTEDATA_LEN 5122 // 5 KiB + 2 bytes (16 bits) for length
#define AEM_ADMINDATA_LEN 9216 // 9 KiB

int addAccount(const unsigned char pk[crypto_box_PUBLICKEYBYTES]);
int setAccountLevel(const char pk_hex[16], const int level);
int destroyAccount(const int64_t upk64);

int64_t addressToHash(const unsigned char addr[18], const unsigned char hashKey[16]);

int getPublicKeyFromAddress(const unsigned char addr[18], unsigned char pk[32], const unsigned char hashKey[16], int *memberLevel);
int getUserInfo(const int64_t upk64, uint8_t * const level, unsigned char ** const noteData, unsigned char ** const addrData, uint16_t * const lenAddr, unsigned char ** const gkData, uint16_t * const lenGk);
int getAdminData(unsigned char ** const adminData);
unsigned char *getUserMessages(const int64_t upk64, uint8_t * const msgCount, const size_t maxSize);

int addUserMessage(const int64_t upk64, const unsigned char *msgData, const size_t msgLen);

int deleteMessages(const int64_t upk64, const int ids[], const int count);
int deleteAddress(const int64_t upk64, const int64_t hash, const unsigned char *addrData, const size_t lenAddrData);
int updateAddress(const int64_t upk64, const unsigned char *addrData, const size_t lenAddrData);
int addAddress(const int64_t upk64, const int64_t hash);

int updateGatekeeper(const unsigned char ownerPk[crypto_box_PUBLICKEYBYTES], char * const gkData, const size_t lenGkData, const unsigned char hashKey[16]);
int updateNoteData(const int64_t upk64, const unsigned char *noteData);

int isUserAdmin(const int64_t upk64);

#endif
