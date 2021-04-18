#ifndef AEM_ACCOUNT_IO_H
#define AEM_ACCOUNT_IO_H

#include <stdbool.h>

int ioSetup(const unsigned char * const newAccountKey, const unsigned char * const newSaltShield);
void ioFree(void);

int userNumFromPubkey(const unsigned char * const pubkey);

void api_account_browse(const int sock, const int num);
void api_account_create(const int sock, const int num);
void api_account_delete(const int sock, const int num);
void api_account_update(const int sock, const int num);

void api_address_create(const int sock, const int num);
void api_address_delete(const int sock, const int num);
void api_address_update(const int sock, const int num);

void api_message_sender(const int sock, const int num);
void api_private_update(const int sock, const int num);
void api_setting_limits(const int sock, const int num);

void api_internal_adrpk(const int sock, const int num);
void api_internal_level(const int sock, const int num);
void api_internal_myadr(const int sock, const int num);
void api_internal_uinfo(const int sock, const int num);
void api_internal_pubks(const int sock, const int num);

void mta_shieldExist(const int sock, const unsigned char * const addr32);
void mta_getPubKey(const int sock, const unsigned char * const addr32, const bool isShield);

#endif
