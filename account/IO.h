#ifndef AEM_ACCOUNT_IO_H
#define AEM_ACCOUNT_IO_H

#include <sodium.h>

#include "../Common/AEM_KDF.h"
#include "../Common/api_req.h"

// main
int ioSetup(const unsigned char baseKey[AEM_KDF_SUB_KEYLEN]);
void ioFree(void);
void setRsaKeys(const unsigned char * const keyAdmin, const size_t lenKeyAdmin, const unsigned char * const keyUsers, const size_t lenKeyUsers);

// IntCom_Action
bool api_auth(unsigned char * const res, union aem_req * const req, const bool post);
void decreaseLastBinTs(void);

// API: Special
int32_t api_invalid(unsigned char * const res);

// API: GET
int32_t api_account_browse(unsigned char * const res);
int32_t api_account_delete(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]);
int32_t api_account_update(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]);
int32_t api_address_create(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]);
int32_t api_address_delete(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]);
int32_t api_address_update(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]);
int32_t api_message_browse(unsigned char * const res, unsigned char flags);
int32_t api_setting_limits(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN]);

// API: POST (Continue)
int32_t api_account_create(unsigned char * const res, const unsigned char * const data, const size_t lenData);
int32_t api_private_update(unsigned char * const res,       unsigned char * const data, const size_t lenData);

// API: POST (Status)
int32_t api_message_create(unsigned char * const res, const unsigned char reqData[AEM_API_REQ_DATA_LEN], const int flags);

// MTA
int32_t mta_getUid(const unsigned char * const addr32, unsigned char **res);

// Storage
int32_t sto_uid2keys(const uint16_t uid, unsigned char **res);

#endif
