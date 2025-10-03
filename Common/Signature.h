#ifndef AEM_SIGNATURE_H
#define AEM_SIGNATURE_H

#include "../Global.h"
#include "Message.h"

void setSigKey(const unsigned char baseKey[AEM_KDF_SUB_KEYLEN]);
void delSigKey(void);

void aem_sign_message(unsigned char * const msg, const size_t lenMsg, const unsigned char usk[AEM_USK_KEYLEN]);
bool aem_sig_verify(const unsigned char uHash[53], const unsigned char sHash_test[27]);

#endif
