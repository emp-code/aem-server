#ifndef AEM_GLOBAL_H
#define AEM_GLOBAL_H

#include <sodium.h>

#include "Common/AEM_KDF.h"
#include "Config.h"

#define AEM_BINTS_BEGIN 1735689600000 // 2025-01-01 00:00:00 UTC

#define AEM_FD_SYSLOG 0
#define AEM_FD_SOCK_MAIN 1
#define AEM_FD_SOCK_CLIENT 2

#define AEM_FD_PIPE_RD 3
#define AEM_FD_PIPE_WR 4
#define AEM_FD_ROOT AEM_FD_PIPE_WR

#define AEM_API_BODY_KEYSIZE (crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_KEYBYTES)

#define AEM_INTCOM_SOCKPATH_LEN 23
#define AEM_INTCOM_SOCKPATH_ACCOUNT "\0All-Ears Mail: Account"
#define AEM_INTCOM_SOCKPATH_DELIVER "\0All-Ears Mail: Deliver"
#define AEM_INTCOM_SOCKPATH_ENQUIRY "\0All-Ears Mail: Enquiry"
#define AEM_INTCOM_SOCKPATH_STORAGE "\0All-Ears Mail: Storage"

#define AEM_INTCOM_MAXSIZE AEM_EVP_MAXSIZE
#define AEM_INTCOM_RESPONSE_OK       INT32_MIN // -48
#define AEM_INTCOM_RESPONSE_CONTINUE (INT32_MIN + 1) // -47
#define AEM_INTCOM_RESPONSE_ERR      (INT32_MIN + 2) // -46

#define AEM_INTCOM_RESPONSE_AUTH_REPLAY   (INT32_MIN + 3) // -45
#define AEM_INTCOM_RESPONSE_AUTH_TIMEDIFF (INT32_MIN + 4) // -44
#define AEM_INTCOM_RESPONSE_AUTH_NOTEXIST (INT32_MIN + 5) // -43
#define AEM_INTCOM_RESPONSE_AUTH_DECRYPT  (INT32_MIN + 6) // -42
#define AEM_INTCOM_RESPONSE_AUTH_KEYSET   (INT32_MIN + 7) // -41
#define AEM_INTCOM_RESPONSE_AUTH_LEVEL    (INT32_MIN + 8) // -40

#define AEM_INTCOM_RESPONSE_USAGE    (INT32_MIN +  9) // -39
#define AEM_INTCOM_RESPONSE_PERM     (INT32_MIN + 10) // -38
#define AEM_INTCOM_RESPONSE_EXIST    (INT32_MIN + 11) // -37
#define AEM_INTCOM_RESPONSE_NOTEXIST (INT32_MIN + 12) // -36
#define AEM_INTCOM_RESPONSE_PARTIAL  (INT32_MIN + 13) // -35
#define AEM_INTCOM_RESPONSE_LIMIT    (INT32_MIN + 14) // -34
#define AEM_INTCOM_RESPONSE_FORBID   (INT32_MIN + 15) // -33

#define AEM_INTCOM_OP_GET 1
#define AEM_INTCOM_OP_POST 2
#define AEM_INTCOM_OP_BROWSE_NEW UINT16_MAX
#define AEM_INTCOM_OP_BROWSE_OLD (UINT16_MAX - 1)

enum aem_internal_enquiry {
	AEM_ENQUIRY_MX,
	AEM_ENQUIRY_A,
	AEM_ENQUIRY_IP,
	AEM_ENQUIRY_DKIM
};

#define AEM_USERCOUNT 4096
#define AEM_ADDRESSES_PER_USER 31 // (2^5)-1
#define AEM_LEN_PRIVATE (AEM_USER_SIZE - AEM_KDF_UAK_KEYLEN - AEM_USK_KEYLEN - AEM_PWK_KEYLEN - AEM_PSK_KEYLEN - AEM_PQK_KEYLEN - 8 - AEM_ADDRESSES_PER_USER - (8 * AEM_ADDRESSES_PER_USER))
#define AEM_LEN_UINFO (4 + (AEM_ADDRESSES_PER_USER * 9) + AEM_LEN_PRIVATE)

// Key lengths
#define X25519_PKBYTES crypto_scalarmult_BYTES
#define X25519_SKBYTES crypto_scalarmult_SCALARBYTES

#define AEM_SSK_KEYLEN 32 // Server Signature Key
#define AEM_USK_KEYLEN 32 // User Signature Key
#define AEM_PWK_KEYLEN X25519_PKBYTES
#define AEM_PSK_KEYLEN 56
#define AEM_PQK_KEYLEN 1568

// Address flags
#define AEM_ADDR_FLAG_SHIELD 128
// 64 unused
#define AEM_ADDR_FLAG_ORIGIN 32
#define AEM_ADDR_FLAG_SECURE 16
#define AEM_ADDR_FLAG_ATTACH  8
#define AEM_ADDR_FLAG_ALLVER  4
#define AEM_ADDR_FLAG_ACCEXT  2
#define AEM_ADDR_FLAG_ACCINT  1
#define AEM_ADDR_FLAGS_DEFAULT (AEM_ADDR_FLAG_ACCEXT | AEM_ADDR_FLAG_ALLVER | AEM_ADDR_FLAG_ATTACH)

#define AEM_SMTP_CHUNKSIZE 65536
#define AEM_SMTP_MAX_SIZE_BODY      4194304 // 4 MiB. RFC5321: min. 64k
#define AEM_SMTP_MAX_SIZE_BODY_STR "4194304"
#define AEM_SMTP_MAX_TO 128 // RFC5321: must accept 100 recipients at minimum
#define AEM_MAXNUM_ATTACHMENTS 31

#define AEM_ADDR32_BINLEN 10
#define AEM_ADDR32_MAXLEN 16 // 80/5=16; 10*8 total bits, 5 bits per character (2^5=32)
#define AEM_ADDR32_ADMIN  (const unsigned char[AEM_ADDR32_BINLEN]) {'\xa6', '\xd0', '\x35', '\x0e', '\x75', '\x85', '\x68', '\x18'} // 'administrator' in Addr32
#define AEM_ADDR32_SYSTEM (const unsigned char[AEM_ADDR32_BINLEN]) {'\x36', '\x7d', '\x9d', '\x3a', '\x80', '\x00', '\x00', '\x00', '\x00', '\x00'} // 'system' in Addr32

#define AEM_MAXPROCESSES 256
#define AEM_MANAGER_RESLEN_DEC (AEM_MAXPROCESSES * 5 * 4)
#define AEM_MANAGER_RESLEN_ENC (AEM_MANAGER_RESLEN_DEC + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES)
#define AEM_MANAGER_CMDLEN_DEC 6
#define AEM_MANAGER_CMDLEN_ENC (AEM_MANAGER_CMDLEN_DEC + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES)

#define AEM_USERLEVEL_MAX 3
#define AEM_USERLEVEL_MIN 0

#ifdef AEM_ADDRESS_NOPWHASH
	#define AEM_SALTNORMAL_LEN crypto_shorthash_KEYBYTES
#else
	#define AEM_SALTNORMAL_LEN crypto_pwhash_SALTBYTES
#endif

// Control-Enriched Text (CET)
	// Tags AEM closes automatically
#define AEM_CET_CHAR_LNK 0x01 // Document link (+1 = HTTPS)
#define AEM_CET_CHAR_FIL 0x03 // File link (+1 = HTTPS)
	// 0x05..0x09 unused
	// Tags with no open/close
#define AEM_CET_CHAR_LBR 0x0A // Linebreak (same as ASCII)
#define AEM_CET_CHAR_HRL 0x0B // Horizontal line
	// 0x0C..0x10 unused
	// Tags with open/close based on the input HTML
#define AEM_CET_THRESHOLD_MANUAL 0x11
#define AEM_CET_CHAR_BIG 0x11 // Big text
#define AEM_CET_CHAR_SML 0x12 // Small text
#define AEM_CET_CHAR_SUB 0x13 // Subscript
#define AEM_CET_CHAR_SUP 0x14 // Superscript
#define AEM_CET_CHAR_MNO 0x15 // Monospace
#define AEM_CET_CHAR_BLD 0x16 // Bold
#define AEM_CET_CHAR_ITA 0x17 // Italics
#define AEM_CET_CHAR_UNL 0x18 // Underline
#define AEM_CET_CHAR_STR 0x19 // Strikethrough
#define AEM_CET_THRESHOLD_LAYOUT 0x1A
#define AEM_CET_CHAR_TBL 0x1A // table
#define AEM_CET_CHAR_TTR 0x1B // tr
#define AEM_CET_CHAR_TTD 0x1C // td
#define AEM_CET_CHAR_LOL 0x1D // ol
#define AEM_CET_CHAR_LUL 0x1E // ul
#define AEM_CET_CHAR_LLI 0x1F // li
// Internal use
#define AEM_CET_CHAR_SEP 127 // Separator

// Message/Envelope constants
#define AEM_EVP_BLOCKSIZE 32
#define AEM_EVP_MINBLOCKS 3 // Header + X25519 + Content
#define AEM_EVP_MAXSIZE 2097216 // ((2^16 - 1) + 3) * 32
#define AEM_EVP_W_OVERHEAD (1 + AEM_PWK_KEYLEN)
#define AEM_EVP_S_OVERHEAD (1 + AEM_PSK_KEYLEN)
#define AEM_MSG_W_MAXSIZE (AEM_EVP_MAXSIZE - AEM_EVP_W_OVERHEAD)
#define AEM_MSG_S_MAXSIZE (AEM_EVP_MAXSIZE - AEM_EVP_S_OVERHEAD)
#define AEM_MSG_HDR_SZ 32
#define AEM_MSG_TYPE_EXT 0
#define AEM_MSG_TYPE_INT 1
#define AEM_MSG_TYPE_OUT 2
#define AEM_MSG_TYPE_UPL 3

// Paths
#define AEM_PATH_HOME "/var/lib/allears"
#define AEM_PATH_DATA AEM_PATH_HOME"/Data"
#define AEM_PATH_MOUNTDIR AEM_PATH_HOME"/mount"

// Misc
#define AEM_TIMEOUT_MANAGER_RCV 10
#define AEM_TIMEOUT_MANAGER_SND 10

#define AEM_MAXLEN_OURDOMAIN 32
#define AEM_MAXLEN_EXEC 163840 // 160 KiB
#define AEM_MAXLEN_DATAFILE 99999

// API commands
enum aem_api_command_get {
	AEM_API_ACCOUNT_BROWSE, // 0
	AEM_API_ACCOUNT_DELETE, // 1
	AEM_API_ACCOUNT_PERMIT, // 2
	AEM_API_ACCOUNT_UPDATE, // 3
	AEM_API_ADDRESS_CREATE, // 4
	AEM_API_ADDRESS_DELETE, // 5
	AEM_API_MESSAGE_BROWSE, // 6
	AEM_API_MESSAGE_DELETE, // 7
	AEM_API_SETTING_LIMITS  // 8
};

enum aem_api_command_post {
	AEM_API_ACCOUNT_KEYSET, // 0
	AEM_API_ADDRESS_UPDATE, // 1
	AEM_API_MESSAGE_CREATE, // 2
	AEM_API_MESSAGE_SENDER, // 3
	AEM_API_MESSAGE_UPLOAD, // 4
	AEM_API_MESSAGE_VERIFY, // 5
	AEM_API_PRIVATE_UPDATE  // 6
};

// API flags
#define AEM_API_MESSAGE_BROWSE_FLAG_OLDER 1 // Older, instead of newer
#define AEM_API_MESSAGE_BROWSE_FLAG_UINFO 2 // Include user info
#define AEM_API_MESSAGE_CREATE_FLAG_E2EE  1 // End-to-end encrypted
#define AEM_API_MESSAGE_CREATE_FLAG_PUB   2 // Public: send to all users
#define AEM_API_MESSAGE_CREATE_FLAG_EMAIL 3 // Send email, not internal mail
#define AEM_API_MESSAGE_DELETE_FLAG_EMPTY 1 // Empty storage completely

// API constants
#define AEM_API_REQ_LEN_BASE64 56
#define AEM_API_REQ_LEN 42
#define AEM_API_REQ_DATA_LEN 20
#define AEM_LEN_APIRESP_BASE (4L + AEM_API_REQ_DATA_LEN + AEM_API_BODY_KEYSIZE + AEM_API_BODY_KEYSIZE)

// IntCom
enum aem_acc_commands {
	AEM_ACC_STORAGE_LEVELS,
	AEM_ACC_STORAGE_CREATE,
	AEM_ACC_STORAGE_DELETE,
	AEM_ACC_STORAGE_LIMITS,
	AEM_ACC_STORAGE_AMOUNT
};

// Process types
enum aem_process_types {
	AEM_PROCESSTYPE_ACC,
	AEM_PROCESSTYPE_DLV,
	AEM_PROCESSTYPE_ENQ,
	AEM_PROCESSTYPE_STO,
	AEM_PROCESSTYPE_REG,
	AEM_PROCESSTYPE_WEB,
	AEM_PROCESSTYPE_API,
	AEM_PROCESSTYPE_MTA,
	AEM_PROCESSTYPES_COUNT
};

// XXX The above and below lists MUST be in the same order

#define AEM_PATH_EXE { \
	AEM_PATH_HOME"/bin/aem-acc", \
	AEM_PATH_HOME"/bin/aem-dlv", \
	AEM_PATH_HOME"/bin/aem-enq", \
	AEM_PATH_HOME"/bin/aem-sto", \
	AEM_PATH_HOME"/bin/aem-reg", \
	AEM_PATH_HOME"/bin/aem-web", \
	AEM_PATH_HOME"/bin/aem-api", \
	AEM_PATH_HOME"/bin/aem-mta"  \
}

#define AEM_NICE { \
	/*acc*/ -16, \
	/*dlv*/  -3, \
	/*enq*/ -10, \
	/*sto*/ -18, \
	/*reg*/   8, \
	/*web*/   4, \
	/*api*/  -4, \
	/*mta*/  -8  \
}

#endif
