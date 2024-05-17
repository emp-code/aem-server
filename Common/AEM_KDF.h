#ifndef AEM_KDF_H
#define AEM_KDF_H

#include <sodium.h>

// UMK: last keybyte always zero
#define AEM_KDF_MASTER_KEYLEN 46 // 32 Key + 12 Nonce + 2 Counter (368 bits)
#define AEM_KDF_SUB_KEYLEN 37 // 32 Key + 4 Nonce + 1 Counter (296 bits)

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

	// User: User Access Key
	AEM_KDF_KEYID_UAK_UID = 0x01  // UserID key
};

void aem_kdf_master(unsigned char * const out, const size_t lenOut, const uint8_t id, const unsigned char key[AEM_KDF_MASTER_KEYLEN]);
void aem_kdf_sub(unsigned char * const out, const size_t lenOut, const uint64_t n, const unsigned char key[AEM_KDF_SUB_KEYLEN]);
uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_SUB_KEYLEN]);

#endif
