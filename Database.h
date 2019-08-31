#ifndef AEM_DATABASE_H
#define AEM_DATABASE_H

#include <stdbool.h>

#define AEM_NOTEDATA_LEN 5122 // 5 KiB + 2 bytes (16 bits) for length
#define AEM_ADMINDATA_LEN 9216 // 9 KiB

int addAccount(const unsigned char * const pk);
int setAccountLevel(const int64_t upk64, const int level);
int destroyAccount(const int64_t upk64);

int64_t addressToHash(const unsigned char * const addr, const unsigned char * const addrKey);
bool isBlockedByGatekeeper(const int16_t * const countryCode, const char *domain, const size_t lenDomain, const char* from, const size_t lenFrom, const int64_t upk64, const unsigned char * const hashKey);

bool upk64Exists(const int64_t upk64);
int getPublicKeyFromAddress(const unsigned char * const addr, unsigned char * const pk, const unsigned char * const addrKey);

int getUserInfo(const int64_t upk64, uint8_t * const level, unsigned char ** const noteData, unsigned char ** const addrData, uint16_t * const lenAddr, unsigned char ** const gkData, uint16_t * const lenGk);
int getAdminData(unsigned char ** const adminData);
unsigned char *getUserMessages(const int64_t upk64, uint8_t * const msgCount, const size_t maxSize);

int addUserMessage(const int64_t upk64, const unsigned char * const msgData, const size_t msgLen);

int deleteMessages(const int64_t upk64, const uint8_t * const ids, const int count);
int deleteAddress(const int64_t upk64, const int64_t hash, const unsigned char * const addrData, const size_t lenAddrData);
int updateAddress(const int64_t upk64, const unsigned char * const addrData, const size_t lenAddrData);
int addAddress(const int64_t upk64, const int64_t hash);

int updateGatekeeper(const unsigned char * const ownerPk, char * const gkData, const size_t lenGkData, const unsigned char * const hashKey);
int updateNoteData(const int64_t upk64, const unsigned char * const noteData);

int getUserLevel(const int64_t upk64);

#endif
