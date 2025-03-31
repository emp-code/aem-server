#ifndef AEM_SIGNATURE_H
#define AEM_SIGNATURE_H

#include "../Global.h"
#include "Message.h"

void setSigKey(const unsigned char * const newKey);
void delSigKey(void);

void aem_sign_message(unsigned char * const msg, const size_t lenMsg, const unsigned char usk[AEM_USK_KEYLEN]);
bool aem_sig_verify(const unsigned char uHash[54], const unsigned char sHash_test[27]);

#endif
