#ifndef AEM_KDF_H
#define AEM_KDF_H

#include <sodium.h>

#define AEM_KDF_SMK_KEYLEN 46 // 32 Key + 12 Nonce + 2 Counter (368 bits)
#define AEM_KDF_UMK_KEYLEN 45 // 32 Key + 12 Nonce + 1 Counter (360 bits)
#define AEM_KDF_SUB_KEYLEN 40 // 32 Key + 8 Nonce (320 bits)

enum {
	// Server: Server Master Key
	AEM_KDF_KEYID_SMK_UMK = 0x01, // Master Admin's UMK
	AEM_KDF_KEYID_SMK_LCH = 0x02, // Launch Key
	AEM_KDF_KEYID_SMK_MNG = 0x03, // Manager Key

	AEM_KDF_KEYID_SMK_ACC = 0x10, // Account Base Key
	AEM_KDF_KEYID_SMK_STO = 0x12, // Storage Base Key
	AEM_KDF_KEYID_SMK_API = 0x13, // API Base Key

	// Server: Account Base Key
	AEM_KDF_KEYID_ACC_ACC = 0x20, // Account Key
	AEM_KDF_KEYID_ACC_NRM = 0x21, // Normal Salt
	AEM_KDF_KEYID_ACC_SHD = 0x22, // Shield Salt
	AEM_KDF_KEYID_ACC_REG = 0x04, // Server Registration Key (SRK)

	// Server: Storage Base Key
	AEM_KDF_KEYID_STO_STI = 0x30, // Stindex Key
	AEM_KDF_KEYID_STO_SIG = 0x31, // Signature Key
	AEM_KDF_KEYID_STO_EID = 0x32, // Encoded UserID

	// Server: API Base Key
	AEM_KDF_KEYID_API_MIA = 0x40,	// MessageID AES Key
	AEM_KDF_KEYID_API_MIC = 0x41,	// MessageID Charset Key

	// User: User Master Key
	AEM_KDF_KEYID_UMK_UAK = 0x01, // User Access Key
	AEM_KDF_KEYID_UMK_ESK = 0x02, // Envelope Secret Key
	AEM_KDF_KEYID_UMK_USK = 0x06, // User Signature Key

	// User: User Access Key
	AEM_KDF_KEYID_UAK_UID = 0x01  // UserID key
};

void aem_kdf_smk(unsigned char * const out, const size_t lenOut, const uint8_t n, const unsigned char smk[AEM_KDF_SMK_KEYLEN]);
void aem_kdf_sub(unsigned char * const out, const size_t lenOut, const uint64_t n, const unsigned char key[AEM_KDF_SUB_KEYLEN]);
uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_SUB_KEYLEN]);

#ifdef AEM_KDF_UMK
void aem_kdf_umk(unsigned char * const out, const size_t lenOut, const uint16_t n, const unsigned char umk[AEM_KDF_UMK_KEYLEN]);
#endif

#endif
