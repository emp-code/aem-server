#ifndef AEM_GLOBAL_H
#define AEM_GLOBAL_H

#include <sodium.h>

#include "Common/AEM_KDF.h"
#include "Config.h"

#define UINT24_MAX 16777215UL
#define AES256_KEYBYTES 32
#define X25519_PKBYTES crypto_scalarmult_BYTES
#define X25519_SKBYTES crypto_scalarmult_SCALARBYTES

#define AEM_FD_BINARY 0
#define AEM_FD_PIPE_RD 1
#define AEM_FD_PIPE_WR 2
#define AEM_FD_ROOT 2

#define AEM_FD_SOCK_MAIN 0
// syslog 1
#define AEM_FD_SOCK_CLIENT 2

#define AEM_APIREQ_CONTAINER_RAW_LEN 75
#define AEM_APIREQ_CONTAINER_MAIN_LEN 23
#define AEM_API_BODY_KEYSIZE crypto_aead_aes256gcm_KEYBYTES
#define AEM_ACC_API_TYPE_GET 0
#define AEM_ACC_API_TYPE_POST_AUTH 1
#define AEM_ACC_API_TYPE_POST_FULL 2

#define AEM_INTCOM_SOCKPATH_LEN 23
#define AEM_INTCOM_SOCKPATH_ACCOUNT "\0All-Ears Mail: Account"
#define AEM_INTCOM_SOCKPATH_DELIVER "\0All-Ears Mail: Deliver"
#define AEM_INTCOM_SOCKPATH_ENQUIRY "\0All-Ears Mail: Enquiry"
#define AEM_INTCOM_SOCKPATH_STORAGE "\0All-Ears Mail: Storage"

#define AEM_INTCOM_MAXSIZE (AEM_MSG_MAXSIZE + AEM_ENVELOPE_RESERVED_LEN)
#define AEM_INTCOM_RESPONSE_OK       INT32_MIN
#define AEM_INTCOM_RESPONSE_CONTINUE (INT32_MIN + 1)
#define AEM_INTCOM_RESPONSE_ERR      (INT32_MIN + 2)
#define AEM_INTCOM_RESPONSE_AUTHFAIL (INT32_MIN + 3)
#define AEM_INTCOM_RESPONSE_USAGE    (INT32_MIN + 4)
#define AEM_INTCOM_RESPONSE_PERM     (INT32_MIN + 5)
#define AEM_INTCOM_RESPONSE_EXIST    (INT32_MIN + 6)
#define AEM_INTCOM_RESPONSE_NOTEXIST (INT32_MIN + 7)
#define AEM_INTCOM_RESPONSE_PARTIAL  (INT32_MIN + 8)
#define AEM_INTCOM_RESPONSE_LIMIT    (INT32_MIN + 9)
#define AEM_INTCOM_RESPONSE_FORBID   (INT32_MIN + 10)

#define AEM_INTCOM_OP_GET 1
#define AEM_INTCOM_OP_POST 2
#define AEM_INTCOM_OP_BROWSE UINT16_MAX

enum aem_internal_enquiry {
	AEM_ENQUIRY_MX,
	AEM_ENQUIRY_A,
	AEM_ENQUIRY_IP,
	AEM_ENQUIRY_DKIM
};

#define AEM_USERCOUNT 4096
#define AEM_ADDRESSES_PER_USER 31 // (2^5)-1
#define AEM_LEN_UINFO (4 + (AEM_ADDRESSES_PER_USER * 9) + AEM_LEN_PRIVATE)
#define AEM_LEN_PRIVATE (AEM_USER_SIZE - 6 - AEM_KDF_KEYSIZE - X25519_PKBYTES - (AEM_ADDRESSES_PER_USER * 17))

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

#define AEM_MAXPROCESSES 100
#define AEM_MANAGER_RESLEN_DEC (AEM_MAXPROCESSES * 5 * 4)
#define AEM_MANAGER_RESLEN_ENC (AEM_MANAGER_RESLEN_DEC + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES)
#define AEM_MANAGER_CMDLEN_DEC 6
#define AEM_MANAGER_CMDLEN_ENC (AEM_MANAGER_CMDLEN_DEC + crypto_aead_aegis256_NPUBBYTES + crypto_aead_aegis256_ABYTES)

#define AEM_USERLEVEL_MAX 3
#define AEM_USERLEVEL_MIN 0

#define AEM_FLAG_UINFO 2
#define AEM_FLAG_NEWER 1

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

#define AEM_MSG_SIG_LEN 16
#define AEM_ENVELOPE_RESERVED_LEN X25519_PKBYTES + AEM_MSG_SIG_LEN

/*
	Minimum block count: start from this number, not zero. Covers overhead, allows larger messages.
	Base: 5 (info + ts) + 64 (sig) + 48 (sealed box) = 117
	ExtMsg: 29/146; 31B .. 1M + 30B
	UplMsg: 17/134; 43B .. 1M + 42B = 1048618 (Attachment, body + filename)
	UplMsg: 41/158; 19B .. 1M + 18B = 1048594 (Upload, body + filename)
	IntMsg: 54/171: 6B ..
	OutMsg: 22/139: 38B .. (IntMsg, no E2EE)
*/
#define AEM_MSG_MAXSIZE 1048752 // ((2^16 - 1) + 12) * 16 = 1048752; 1M + 176B
#define AEM_MSG_MINBLOCKS 12
#define AEM_MSG_MINSIZE (AEM_MSG_MINBLOCKS * 16) // 12 * 16 = 192 (-15 --> 177 min)
#define AEM_MSG_MINSIZE_DEC (AEM_MSG_MINSIZE - X25519_PKBYTES - AEM_MSG_SIG_LEN) // 177 - 32 - 16 = 129

#define AEM_PATH_HOME "/var/lib/allears"
#define AEM_PATH_MOUNTDIR AEM_PATH_HOME"/mount"

#define AEM_TIMEOUT_MANAGER_RCV 10
#define AEM_TIMEOUT_MANAGER_SND 10

#define AEM_MAXSIZE_EXEC 131072 // 128 KiB

enum aem_api_command_get {
	AEM_API_ACCOUNT_BROWSE,
	AEM_API_ACCOUNT_DELETE,
	AEM_API_ACCOUNT_UPDATE,
	AEM_API_ADDRESS_CREATE,
	AEM_API_ADDRESS_DELETE,
	AEM_API_ADDRESS_LOOKUP,
	AEM_API_ADDRESS_UPDATE,
	AEM_API_MESSAGE_BROWSE,
	AEM_API_MESSAGE_DELETE,
	AEM_API_MESSAGE_SENDER,
	AEM_API_SETTING_LIMITS
};

enum aem_api_command_post {
	AEM_API_ACCOUNT_CREATE,
	AEM_API_MESSAGE_CREATE,
	AEM_API_MESSAGE_PUBLIC,
	AEM_API_MESSAGE_UPLOAD,
	AEM_API_MESSAGE_VERIFY,
	AEM_API_PRIVATE_UPDATE
};

#define AEM_API_MESSAGE_BROWSE_FLAG_PAD1M 1 // Pad response to max size (1M)
#define AEM_API_MESSAGE_BROWSE_FLAG_UINFO 2 // Include user info
#define AEM_API_MESSAGE_BROWSE_FLAG_OLDER 4 // Older, instead of newer
#define AEM_API_MESSAGE_BROWSE_FLAG_MSGID 8 // Start from the message with this MessageID

enum aem_mta_commands {
	AEM_MTA_GETUID_NORMAL,
	AEM_MTA_GETUID_SHIELD
};

enum aem_acc_commands {
	AEM_ACC_STORAGE_LEVELS,
	AEM_ACC_STORAGE_CREATE,
	AEM_ACC_STORAGE_DELETE,
	AEM_ACC_STORAGE_LIMITS,
	AEM_ACC_STORAGE_AMOUNT
};

enum aem_process_types {
	AEM_PROCESSTYPE_WEB,
	AEM_PROCESSTYPE_API,
	AEM_PROCESSTYPE_MTA,
	AEM_PROCESSTYPE_ACCOUNT,
	AEM_PROCESSTYPE_DELIVER,
	AEM_PROCESSTYPE_ENQUIRY,
	AEM_PROCESSTYPE_STORAGE,
	AEM_PROCESSTYPES_COUNT
};

// XXX The above and below lists MUST be in the same order

#define AEM_PATH_EXE { \
	AEM_PATH_HOME"/bin/aem-web", \
	AEM_PATH_HOME"/bin/aem-api", \
	AEM_PATH_HOME"/bin/aem-mta", \
	AEM_PATH_HOME"/bin/aem-account", \
	AEM_PATH_HOME"/bin/aem-deliver", \
	AEM_PATH_HOME"/bin/aem-enquiry", \
	AEM_PATH_HOME"/bin/aem-storage" \
}

#define AEM_NICE { \
	/*Web*/   4, \
	/*API*/  -4, \
	/*MTA*/  -8, \
	/*Account*/ -16, \
	/*Deliver*/  -3, \
	/*Enquiry*/ -10, \
	/*Storage*/ -18 \
}

#endif
