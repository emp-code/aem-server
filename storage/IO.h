#ifndef AEM_STORAGE_IO_H
#define AEM_STORAGE_IO_H

#include <stdint.h>

#include <sodium.h>

#include "../Common/AEM_KDF.h"

// main
void ioSetup(const unsigned char baseKey[AEM_KDF_SUB_KEYLEN]);
void ioFree(void);

// Account
int32_t acc_storage_amount(unsigned char **res);
int32_t acc_storage_create(const unsigned char * const msg, const size_t lenMsg);
int32_t acc_storage_delete(const unsigned char * const msg, const size_t lenMsg);
int32_t acc_storage_levels(const unsigned char * const msg, const size_t lenMsg);
int32_t acc_storage_limits(const unsigned char * const msg, const size_t lenMsg);

// API
int32_t api_internal_erase(const unsigned char * const upk, const size_t lenUpk);
int32_t api_message_browse(const unsigned char * const req, const size_t lenReq, unsigned char ** const out, const bool newer);
int32_t api_message_delete(const unsigned char * const req, const size_t lenReq);

// API/DLV
int32_t storage_write(unsigned char * const req, const size_t lenReq, const uint16_t uid);
int32_t storage_delete(const uint16_t uid, const uint16_t delId);

#endif
