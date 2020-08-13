#ifndef AEM_DELIVERY_H
#define AEM_DELIVERY_H

#include "../Global.h"
#include "Email.h"

void setAccessKey_account(const unsigned char * const newKey);
void setAccessKey_storage(const unsigned char * const newKey);
void setSignKey(const unsigned char * const seed);
void setAccountPid(const pid_t pid);
void setStoragePid(const pid_t pid);

void deliverMessage(const char * const to, const size_t lenToTotal, const unsigned char * const msgBody, size_t lenMsgBody, struct emailInfo *email);

#endif
