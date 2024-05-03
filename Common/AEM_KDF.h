#ifndef AEM_KDF_H
#define AEM_KDF_H

#include <sodium.h>

#define AEM_KDF_KEYSIZE crypto_stream_chacha20_KEYBYTES

typedef enum : uint8_t {
	// Server: Server Master Key
	AEM_KDF_KEYID_SMK_UMK = 0x01, // Master Admin's UMK
	AEM_KDF_KEYID_SMK_BIN = 0x02, // Binary Key
	AEM_KDF_KEYID_SMK_MNG = 0x03, // Manager Key

	AEM_KDF_KEYID_SMK_ACC = 0x10, // Account Base Key
	AEM_KDF_KEYID_SMK_DLV = 0x11, // Deliver Base Key
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
	AEM_KDF_KEYID_UMK_ESK = 0x02,  // Envelope Secret Key

	// User: User Access Key
	AEM_KDF_KEYID_UAK_UID = 0x10, // UserID key
	AEM_KDF_KEYID_UAK_EAK = 0x11 // Envelope Access Key
} aem_kdf_keyId;

void aem_kdf(unsigned char * const out, const size_t lenOut, const uint64_t nonce, const unsigned char key[crypto_stream_chacha20_KEYBYTES]);
void aem_kdf_xor(unsigned char * const target, const size_t lenTarget, const uint64_t nonce, const unsigned char key[crypto_stream_chacha20_KEYBYTES]);
uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_KEYSIZE]);

#endif
