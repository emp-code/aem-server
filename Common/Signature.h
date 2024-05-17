#ifndef AEM_SIGNATURE_H
#define AEM_SIGNATURE_H

#define AEM_SIG_KEYLEN 32

void setSigKey(const unsigned char * const newKey);
void delSigKey(void);

void aem_sign_message(unsigned char * const msg, const size_t lenMsg);
bool aem_sig_verify(const unsigned char * const baseHash, const unsigned char * const sig);

#endif
