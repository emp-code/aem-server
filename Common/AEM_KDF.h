#ifndef AEM_KDF_H
#define AEM_KDF_H

#include <sodium.h>

#define AEM_KDF_SMK_KEYLEN 46 // 32 Key + 12 Nonce + 2 Counter (368 bits)
#define AEM_KDF_UMK_KEYLEN 45 // 32 Key + 12 Nonce + 1 Counter (360 bits)
#define AEM_KDF_UAK_KEYLEN 43
#define AEM_KDF_SUB_KEYLEN 40 // 32 Key + 8 Nonce (320 bits)
#define AEM_KDF_MPK_KEYLEN crypto_aead_aegis256_KEYBYTES

#define AEM_UAK_POST 64

// Server - Server Master Key
	#define AEM_KDF_KEYID_SMK_UMK  1 // Master Admin's UMK
	#define AEM_KDF_KEYID_SMK_LCH  2 // Launch Key
	#define AEM_KDF_KEYID_SMK_MPK  3 // Manager Protocol Key
	#define AEM_KDF_KEYID_SMK_ACC 10 // Account Base Key
//	#define AEM_KDF_KEYID_SMK_DLV 11 // Deliver Base Key
//	#define AEM_KDF_KEYID_SMK_ENQ 12 // Enquiry Base Key
	#define AEM_KDF_KEYID_SMK_STO 13 // Storage Base Key
	#define AEM_KDF_KEYID_SMK_API 14 // API Base Key

// Server - Account Base Key
	#define AEM_KDF_KEYID_ACC_ACC 1 // Account Key
	#define AEM_KDF_KEYID_ACC_NRM 2 // Normal Salt
	#define AEM_KDF_KEYID_ACC_SHD 3 // Shield Salt
	#define AEM_KDF_KEYID_ACC_REG 4 // Server Registration Key (SRK)

// Server - Storage Base Key
	#define AEM_KDF_KEYID_STO_STI 1 // Stindex Key
	#define AEM_KDF_KEYID_STO_SIG 2 // Server Signature Key
	#define AEM_KDF_KEYID_STO_EID 3 // Encoded UserID

// Server - API Base Key
	#define AEM_KDF_KEYID_API_MIA 1	// MessageID AES Key
	#define AEM_KDF_KEYID_API_MIC 2	// MessageID Charset Key

// User - User Master Key
	#define AEM_KDF_KEYID_UMK_UAK  1 // User API Key
	#define AEM_KDF_KEYID_UMK_USK  4 // User Signature Key
	#define AEM_KDF_KEYID_UMK_EWS 12 // Envelope Weak Secret

void aem_kdf_smk(unsigned char * const out, const size_t lenOut, const uint8_t n, const unsigned char smk[AEM_KDF_SMK_KEYLEN]);
void aem_kdf_uak(unsigned char * const out, const size_t lenOut, const uint64_t binTs, const bool post, const uint8_t type, const unsigned char key[AEM_KDF_UAK_KEYLEN]);
void aem_kdf_sub(unsigned char * const out, const size_t lenOut, const uint64_t n, const unsigned char key[AEM_KDF_SUB_KEYLEN]);
uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_UAK_KEYLEN]);

#ifdef AEM_KDF_UMK
void aem_kdf_umk(unsigned char * const out, const size_t lenOut, const uint16_t n, const unsigned char umk[AEM_KDF_UMK_KEYLEN]);
#endif

#endif
