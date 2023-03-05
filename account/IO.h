#ifndef AEM_ACCOUNT_IO_H
#define AEM_ACCOUNT_IO_H

#include <stdbool.h>

#include <sodium.h>

int ioSetup(const unsigned char baseKey[crypto_kdf_KEYBYTES]);
void ioFree(void);

int userNumFromUpk(const unsigned char * const upk);

int32_t api_account_browse(const int num, unsigned char **res);
int32_t api_account_create(const int num, const unsigned char * const msg, const size_t lenMsg);
int32_t api_account_delete(const int num, const unsigned char * const msg, const size_t lenMsg);
int32_t api_account_update(const int num, const unsigned char * const msg, const size_t lenMsg);

int32_t api_address_create(const int num, const unsigned char * const msg, const size_t lenMsg, unsigned char **res);
int32_t api_address_delete(const int num, const unsigned char * const msg, const size_t lenMsg);
int32_t api_address_update(const int num, const unsigned char * const msg, const size_t lenMsg);

int32_t api_private_update(const int num, const unsigned char * const msg, const size_t lenMsg);
int32_t api_setting_limits(const int num, const unsigned char * const msg, const size_t lenMsg);

int32_t api_internal_adrpk(const int num, const unsigned char * const msg, const size_t lenMsg, unsigned char **res);
int32_t api_internal_level(const int num);
int32_t api_internal_myadr(const int num, const unsigned char * const msg, const size_t lenMsg);
int32_t api_internal_uinfo(const int num, unsigned char **res);
int32_t api_internal_pubks(const int num, unsigned char **res);

int32_t mta_getUpk(const unsigned char * const addr32, const bool isShield, unsigned char **res);

#endif
